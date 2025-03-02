macro_rules! cfg_dhcp {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "dhcp")]
            #[cfg_attr(docsrs, doc(cfg(feature = "dhcp")))]
            $item
        )*
    }
}

macro_rules! cfg_libpcap {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "libpcap")]
            #[cfg_attr(docsrs, doc(cfg(feature = "libpcap")))]
            $item
        )*
    }
}

macro_rules! cfg_test_util{
    ($($item:item)*) => {
        $(
            #[cfg(feature = "test-util")]
            #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
            $item
        )*
    }
}
