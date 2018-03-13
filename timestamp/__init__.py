#!/usr/bin/env python3
#
# Electrum Timstamp Plugin
# Copyright (C) 2018 Leonardo Comandini
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# based on
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 Thomas Voegtlin

from electrum.i18n import _

fullname = 'Timestamp'
description = '%s\n%s' % (_("Timestamp your files with your transactions using OpenTimestamps."),
                          _("\nNote: you can timestamp for free using the public calendars, " +
                            "while including a timestamp in your transaction has a cost."))

available_for = ['qt']
