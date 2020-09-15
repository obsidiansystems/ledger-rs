/*******************************************************************************
*   (c) 2018 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

extern crate hidapi;
#[cfg(test)]
#[macro_use]
extern crate serial_test;

use byteorder::{BigEndian, ReadBytesExt};
use cfg_if::cfg_if;
use hidapi::HidDevice;
use lazy_static::lazy_static;
use ledger_apdu::{map_apdu_error_description, APDUAnswer, APDUCommand, APDUErrorCodes};
use log::debug;
use std::cell::RefCell;
use std::ffi::CStr;
use std::io::Cursor;
use std::sync::{Arc, Mutex, Weak};
use thiserror::Error;

cfg_if! {
if #[cfg(target_os = "linux")] {
    #[macro_use]
    extern crate nix;
    extern crate libc;
    use std::mem;
} else {
    // Mock the type in other target_os
    mod nix {
        use thiserror::Error;
        #[derive(Clone, Debug, Error, Eq, PartialEq)]
        pub enum Error {}
    }
}}

const LEDGER_VID: u16 = 0x2c97;
const LEDGER_USAGE_PAGE: u16 = 0xFFA0;
const LEDGER_CHANNEL: u16 = 0x0101;
const LEDGER_PACKET_SIZE: u8 = 64;
const LEDGER_TIMEOUT: i32 = 10_000_000;

#[derive(Error, Debug)]
pub enum LedgerError {
    /// Device not found error
    #[error("Ledger device not found")]
    DeviceNotFound,
    /// Communication error
    #[error("Ledger device: communication error `{0}`")]
    Comm(&'static str),
    /// APDU error
    #[error("Ledger device: APDU error `{0}`")]
    APDU(&'static str),

    /// Ioctl error
    #[error("Ledger device: Ioctl error")]
    Ioctl(#[from] nix::Error),
    /// i/o error
    #[error("Ledger device: i/o error")]
    Io(#[from] std::io::Error),
    /// HID error
    #[error("Ledger device: Io error")]
    Hid(#[from] hidapi::HidError),
    /// UT8F error
    #[error("Ledger device: UTF8 error")]
    UTF8(#[from] std::str::Utf8Error),
}

struct HidApiWrapper {
    _api: RefCell<Weak<Mutex<hidapi::HidApi>>>,
}

unsafe impl Send for HidApiWrapper {}

lazy_static! {
    static ref HIDAPIWRAPPER: Arc<Mutex<HidApiWrapper>> =
        Arc::new(Mutex::new(HidApiWrapper::new()));
}

impl HidApiWrapper {
    fn new() -> Self {
        HidApiWrapper {
            _api: RefCell::new(Weak::new()),
        }
    }

    fn get(&self) -> Result<Arc<Mutex<hidapi::HidApi>>, LedgerError> {
        let tmp = self._api.borrow().upgrade();

        if let Some(api_mutex) = tmp {
            return Ok(api_mutex);
        }

        let hidapi = hidapi::HidApi::new()?;
        let tmp = Arc::new(Mutex::new(hidapi));
        self._api.replace(Arc::downgrade(&tmp));
        Ok(tmp)
    }
}


#[cfg(not(target_os = "linux"))]
fn device_filter_os_impl(device: &hidapi::DeviceInfo) -> bool {
    return device.usage_page() == LEDGER_USAGE_PAGE;
}

#[cfg(target_os = "linux")]
fn device_filter_os_impl(device: &hidapi::DeviceInfo) -> bool {
    let path = device.path();
    match get_usage_page(&path) {
        Ok(usage_page) => {
            return usage_page == LEDGER_USAGE_PAGE;
        }
        Err(_) => {
            return false;
        }
    };
}

fn device_filter(device: &hidapi::DeviceInfo) -> bool {
    return (device.vendor_id() == LEDGER_VID) && device_filter_os_impl(&device);
}

fn find_all_ledger_device_paths(api: &hidapi::HidApi) -> Vec<&CStr> {
    let mut result = Vec::new();
    for device in api.device_list() {
        if device_filter(device) {
            result.push(device.path());
        }
    }
    return result;
}

// Takes a closure that acts on a single ledger, and applies it to all available ledgers
pub fn with_all_ledgers<Action>(action: &mut Action) -> Result<(), LedgerError>
    where
        Action: FnMut(TransportNativeHID) -> Result<(), LedgerError>
{
    let apiwrapper = HIDAPIWRAPPER.lock().expect("Could not lock api wrapper");
    let api_mutex = apiwrapper.get().expect("Error getting api_mutex");
    let mut api = api_mutex.lock().expect("Could not lock");
    let _ = api.refresh_devices()?;
    let device_paths = find_all_ledger_device_paths(&api);
    for path in device_paths {
        let device = api.open_path(&path)?;
        let ledger = TransportNativeHID {
            device: device,
            device_mutex: Mutex::new(0),
        };
        let _ = action(ledger)?;
    }
    return Ok(());
        
}

// Takes a closure that acts on a single ledger, and a filter, and applies the closure to the first
// ledger for which the filter returns 'true'
// This function ensures that a ledger cannot never be opened more than once at a time
// (If it is used recursively, the recursive call should fail with error due to the hidpai lock)
pub fn with_ledger_matching<Filter, Action, T, E>(filter: Filter, action: &mut Action) -> Result<T, E>
    where
        Filter: Fn(&mut TransportNativeHID) -> bool,
        Action: FnMut(TransportNativeHID) -> Result<T, E>,
        E: From<LedgerError>
{
    let apiwrapper = HIDAPIWRAPPER.lock().expect("Could not lock api wrapper");
    let api_mutex = apiwrapper.get().expect("Error getting api_mutex");
    let mut api = api_mutex.lock().expect("Could not lock");
    let _ = api.refresh_devices().map_err(|e| LedgerError::from(e));
    let device_paths = find_all_ledger_device_paths(&api);

    let mut desired = None;
    for path in device_paths {
        let device = api.open_path(&path).map_err(|e| LedgerError::from(e))?;
        let mut ledger = TransportNativeHID {
            device: device,
            device_mutex: Mutex::new(0),
        };
        // Break at first matching elem
        if filter(&mut ledger) {
            desired = Some(ledger);
            break;
        }
    }
    if let Some(ledger) = desired {
        return action(ledger);
    }
    else {
        return Err(E::from(LedgerError::DeviceNotFound))
    }
}

#[allow(dead_code)]
pub struct TransportNativeHID {
    device: HidDevice,
    device_mutex: Mutex<i32>,
}

impl TransportNativeHID {

    fn write_apdu(&self, channel: u16, apdu_command: &[u8]) -> Result<i32, LedgerError> {
        let command_length = apdu_command.len() as usize;
        let mut in_data = Vec::with_capacity(command_length + 2);
        in_data.push(((command_length >> 8) & 0xFF) as u8);
        in_data.push((command_length & 0xFF) as u8);
        in_data.extend_from_slice(&apdu_command);

        let mut buffer = vec![0u8; LEDGER_PACKET_SIZE as usize];
        buffer[0] = ((channel >> 8) & 0xFF) as u8; // channel big endian
        buffer[1] = (channel & 0xFF) as u8; // channel big endian
        buffer[2] = 0x05u8;

        for (sequence_idx, chunk) in in_data
            .chunks((LEDGER_PACKET_SIZE - 5) as usize)
            .enumerate()
        {
            buffer[3] = ((sequence_idx >> 8) & 0xFF) as u8; // sequence_idx big endian
            buffer[4] = (sequence_idx & 0xFF) as u8; // sequence_idx big endian
            buffer[5..5 + chunk.len()].copy_from_slice(chunk);

            debug!("[{:3}] << {:}", buffer.len(), hex::encode(&buffer));

            let result = self.device.write(&buffer);

            match result {
                Ok(size) => {
                    if size < buffer.len() {
                        return Err(LedgerError::Comm(
                            "USB write error. Could not send whole message",
                        ));
                    }
                }
                Err(x) => return Err(LedgerError::Hid(x)),
            }
        }
        Ok(1)
    }

    fn read_apdu(&self, _channel: u16, apdu_answer: &mut Vec<u8>, timeout: Option<i32>) -> Result<usize, LedgerError> {
        let timeout = timeout.unwrap_or(LEDGER_TIMEOUT);
        let mut buffer = vec![0u8; LEDGER_PACKET_SIZE as usize];
        let mut sequence_idx = 0u16;
        let mut expected_apdu_len = 0usize;

        loop {
            let res = self.device.read_timeout(&mut buffer, timeout)?;

            if (sequence_idx == 0 && res < 7) || res < 5 {
                return Err(LedgerError::Comm("Read error. Incomplete header"));
            }

            let mut rdr = Cursor::new(&buffer);

            let _rcv_channel = rdr.read_u16::<BigEndian>()?;
            let _rcv_tag = rdr.read_u8()?;
            let rcv_seq_idx = rdr.read_u16::<BigEndian>()?;

            // TODO: Check why windows returns a different channel/tag
            //        if rcv_channel != channel {
            //            return Err(Box::from(format!("Invalid channel: {}!={}", rcv_channel, channel )));
            //        }
            //        if rcv_tag != 0x05u8 {
            //            return Err(Box::from("Invalid tag"));
            //        }

            if rcv_seq_idx != sequence_idx {
                return Err(LedgerError::Comm("Invalid sequence idx"));
            }

            if rcv_seq_idx == 0 {
                expected_apdu_len = rdr.read_u16::<BigEndian>()? as usize;
            }

            let available: usize = buffer.len() - rdr.position() as usize;
            let missing: usize = expected_apdu_len - apdu_answer.len();
            let end_p = rdr.position() as usize + std::cmp::min(available, missing);

            let new_chunk = &buffer[rdr.position() as usize..end_p];

            debug!("[{:3}] << {:}", new_chunk.len(), hex::encode(&new_chunk));

            apdu_answer.extend_from_slice(new_chunk);

            if apdu_answer.len() >= expected_apdu_len {
                return Ok(apdu_answer.len());
            }

            sequence_idx += 1;
        }
    }

    pub fn exchange(&self, command: &APDUCommand, timeout: Option<i32>) -> Result<APDUAnswer, LedgerError> {
        let _guard = self.device_mutex.lock().unwrap();

        self.write_apdu(LEDGER_CHANNEL, &command.serialize())?;

        let mut answer: Vec<u8> = Vec::with_capacity(256);
        let res = self.read_apdu(LEDGER_CHANNEL, &mut answer, timeout)?;

        if res < 2 {
            return Err(LedgerError::Comm("response was too short"));
        }

        let apdu_answer = APDUAnswer::from_answer(answer);

        if apdu_answer.retcode != APDUErrorCodes::NoError as u16 {
            return Err(LedgerError::APDU(map_apdu_error_description(
                apdu_answer.retcode,
            )));
        }

        Ok(apdu_answer)
    }

    pub fn close() {
        extern crate hidapi;
    }
}

cfg_if! {
if #[cfg(target_os = "linux")] {
    const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

    #[repr(C)]
    pub struct HidrawReportDescriptor {
        size: u32,
        value: [u8; HID_MAX_DESCRIPTOR_SIZE],
    }

    fn get_usage_page(device_path: &CStr) -> Result<u16, LedgerError>
    {
        // #define HIDIOCGRDESCSIZE	_IOR('H', 0x01, int)
        // #define HIDIOCGRDESC		_IOR('H', 0x02, struct HidrawReportDescriptor)
        ioctl_read!(hid_read_descr_size, b'H', 0x01, libc::c_int);
        ioctl_read!(hid_read_descr, b'H', 0x02, HidrawReportDescriptor);

        use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
        use std::fs::OpenOptions;

        let file_name = device_path.to_str()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(file_name)?;

        let mut desc_size = 0;

        unsafe {
            let fd = file.as_raw_fd();

            hid_read_descr_size(fd, &mut desc_size)?;
            let mut desc_raw_uninit = mem::MaybeUninit::<HidrawReportDescriptor>::new(HidrawReportDescriptor {
                size: desc_size as u32,
                value: [0u8; 4096]
            });
            hid_read_descr(fd, desc_raw_uninit.as_mut_ptr())?;
            let desc_raw = desc_raw_uninit.assume_init();

            let data = &desc_raw.value[..desc_raw.size as usize];

            let mut data_len;
            let mut key_size;
            let mut i = 0 as usize;

            while i < desc_size as usize {
                let key = data[i];
                let key_cmd = key & 0xFC;

                if key & 0xF0 == 0xF0 {
                    data_len = 0;
                    key_size = 3;
                    if i + 1 < desc_size as usize {
                        data_len = data[i + 1];
                    }
                } else {
                    key_size = 1;
                    data_len = key & 0x03;
                    if data_len == 3 {
                        data_len = 4;
                    }
                }

                if key_cmd == 0x04 {
                    let usage_page = match data_len {
                        1 => u16::from(data[i + 1]),
                        2 => (u16::from(data[i + 2] )* 256 + u16::from(data[i + 1])),
                        _ => 0 as u16
                    };

                    return Ok(usage_page);
                }

                i += (data_len + key_size) as usize;
            }
        }
        Ok(0)
    }
}}

#[cfg(test)]
mod integration_tests {
    use crate::{APDUCommand, TransportNativeHID, HIDAPIWRAPPER};
    use log::debug;
    use serial_test;

    fn init_logging() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    #[serial]
    fn list_all_devices() {
        init_logging();
        let apiwrapper = HIDAPIWRAPPER.lock().expect("Could not lock api wrapper");
        let api_mutex = apiwrapper.get().expect("Error getting api_mutex");
        let api = api_mutex.lock().expect("Could not lock");

        for device_info in api.device_list() {
            debug!(
                "{:#?} - {:#x}/{:#x}/{:#x}/{:#x} {:#} {:#}",
                device_info.path(),
                device_info.vendor_id(),
                device_info.product_id(),
                device_info.usage_page(),
                device_info.interface_number(),
                device_info.manufacturer_string().unwrap_or_default(),
                device_info.product_string().unwrap_or_default()
            );
        }
    }

    #[test]
    #[serial]
    fn ledger_device_path() {
        init_logging();
        let apiwrapper = HIDAPIWRAPPER.lock().expect("Could not lock api wrapper");
        let api_mutex = apiwrapper.get().expect("Error getting api_mutex");
        let api = api_mutex.lock().expect("Could not lock");

        // TODO: Extend to discover two devices
        let ledger_path =
            TransportNativeHID::find_ledger_device_path(&api).expect("Could not find a device");
        debug!("{:?}", ledger_path);
    }

    #[test]
    #[serial]
    fn serialize() {
        let data = vec![0, 0, 0, 1, 0, 0, 0, 1];

        let command = APDUCommand {
            cla: 0x56,
            ins: 0x01,
            p1: 0x00,
            p2: 0x00,
            data,
        };

        let serialized_command = command.serialize();

        let expected = vec![86, 1, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 1];

        assert_eq!(serialized_command, expected)
    }

    #[test]
    #[serial]
    fn exchange() {
        init_logging();

        let ledger = TransportNativeHID::new().expect("Could not get a device");

        // use app info command that works on almost any app
        // including dashboard
        let command = APDUCommand {
            cla: 0xb0,
            ins: 0x01,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
        };

        let result = ledger.exchange(&command, None).expect("Error during exchange");
        debug!("{:?}", result);
    }
}
