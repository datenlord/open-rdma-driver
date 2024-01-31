use open_rdma_driver::Device;

#[test]
fn device_init() {
    let _emulated = Device::new_emulated();
    let _hardware = Device::new_hardware();
}
