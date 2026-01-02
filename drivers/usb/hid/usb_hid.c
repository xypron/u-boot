#include <dm.h>
#include <usb.h>

static int usb_hid_probe(struct udevice *dev)
{
	struct usb_device *udev = dev_get_parent_priv(dev);

	printf("Probing %s\n", dev->name);

	return 0;
}

static int usb_hid_bind(struct udevice *dev)
{
	printf("Binding %s\n", dev->name);

	return 0;
}

/*
 * The driver must be scanned after usb_kbd. Prepend zz_ for this purpose. */
U_BOOT_DRIVER(zz_usb_hid) = {
	.id	= UCLASS_USB,
	.name	= "usb_hid",
	.bind	= usb_hid_bind,
	.probe	= usb_hid_probe,
};

static const struct usb_device_id hid_id_table[] = {
	{
		.match_flags = USB_DEVICE_ID_MATCH_INT_CLASS,
		.bInterfaceClass = USB_CLASS_HID,
	},
	{ }		/* Terminating entry */
};

U_BOOT_USB_DEVICE(zz_usb_hid, hid_id_table);
