| Copyright 2009 `John Wiseman`_
| Covered by the MIT License, see `LICENSE.txt`_.

4mapper
==========

Introduction
------------

I had been interested in mapping my `Foursquare`_ checkins when I found
Chris Mueller's `Cartographer`_ mapping library and thought its cluster
maps offered some advantages over the obvious heatmap approach.  I
wrote 4mapper to try it out.

Once 4mapper was working I realized it would be fun to see other
people's maps, so I put it on Google's appspot and added the ability
to show other people your checkins.

You can try 4mapper at `http://4mapper.appspot.com/`_.

How it works
------------

When a user authorizes 4mapper to access their Foursquare account, it
grabs their entire checkin history (and name and photo URL) and saves
it.  At no other time does it access your Foursquare account (the
authorization tokens are stored in the user session, not in the
database).

A user can mark their history as public, in which case they appear in
the ``/users`` page, and their checkins can be mapped.

The module 4mapper uses to talk to the Foursquare API is available as
a separate repository: `foursquare-python`_.

Screenshots
-----------

.. image:: http://github.com/wiseman/4mapper/raw/master/screenshots/4mapper-1.jpg

.. image:: http://github.com/wiseman/4mapper/raw/master/screenshots/4mapper-2.jpg


How it doesn't work
--------------------

The site doesn't work at all in Internet Explorer.
				   
4mapper does not do a good job of translating errors into readable
messages.  Usually this comes up when a Foursquare API call times out,
and the Google App Engine throws a DownloadError.

There is a bug in session logic that can result in a History record
with a null history.  The app doesn't deal with null histories well.

There's a Javascript error that pops up sometimes, too; If you see
something about a "null bbox", something has gone wrong inside the
Cartographer library.

It seems that Foursquare sometimes invalidates user photo URLs; Since
4mapper only updates that info when a user authorizes it, we can end
up trying to show bad photo URLs on the ``/users`` page.

This is the closest thing to a webapp I've written in years, and it is
my first Google AppEngine application.  It's probably wrong.



.. _John Wiseman: http://twitter.com/lemonodor
.. _LICENSE.txt: http://github.com/wiseman/4mapper/blob/master/LICENSE.txt
.. _Foursquare: http://foursquare.com/
.. _Cartographer: http://cartographer.visualmotive.com/
.. _http://4mapper.appspot.com/: http://4mapper.appspot.com/
.. _foursquare-python: http://github.com/wiseman/foursquare-python
