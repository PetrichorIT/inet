macro_rules! cfg_dns {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "dns")]
            #[cfg_attr(docsrs, doc(cfg(feature = "dns")))]
            $item
        )*
    }
}

macro_rules! cfg_uds {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "uds")]
            #[cfg_attr(docsrs, doc(cfg(feature = "uds")))]
            $item
        )*
    }
}

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
