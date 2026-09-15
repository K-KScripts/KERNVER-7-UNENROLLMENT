# ManualEscape writeup (extended version)

Last updated: 2026-8-31 7:07 PM PDT

So I took a look at ChromeOS Recovery Images,

ChromeOS recovery images are official tools signed by Google that consumers can install on a USB drive to reinstall ChromeOS onto
Chromebooks and Chromeboxes in case something goes wrong.
In October 2025, I thought I'd familiarize myself with how ChromeOS recovery images work.
I knew that they composed of 3 main steps; initramfs (verification), the installer, and post-install (referred to as postinst).
What I did not know were the internal functioning of these parts.

And one more thing - it turns out that there wasn't a block_devmode check in recovery images until [r42](https://crrev.com/c/202250), which allows us to modify
recovery images in the "intended" way and still have them boot with developer mode blocked. This only applies to very old devices that have r41 recovery images available,
but still somewhat useful. (This also goes up until [r48](https://crrev.com/c/315800) if you remove the WP screw, which accommodates a few more devices.)

And that's about it. At this point, I went on to write the build script and create improved payloads.
The bugs had been reported already, so now I just needed for them to be marked fixed and wait 14 weeks.  
Here we are, August ~~first~~ thirty first, as promised.
