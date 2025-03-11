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
