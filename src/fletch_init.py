"""
Some helper functions for the startup of the integration. The functions
have been placed here to allow for unit testing to be done, instead of
isolating them to the actual init function of the service.
"""
import logging

from cbapi.response.models import Watchlist

from fletch_config import FletchCriticalError

_logger = logging.getLogger(__name__)


def auto_create_vulnerability_watchlist(cb, watchlist_name, feed_descriptors):
    """
    Check to see if the vulnerability watchlist exists. If not, create
    it ourselves.  If it does exist, confirm it is doing the proper search.
    If it isn't properly searching, remove the watchlist and re-create it.
    :param cb: CbAPI Response Handle
    :param watchlist_name:  name of the watchlist we should check against
    :param feed_descriptors: names of the vulnerability feeds to be included
    """

    # build the search syntax parts
    search_feed_syntax = list()
    feed_prefix = 'alliance_score_'
    for feed in feed_descriptors:
        feed_name = feed[0]  # name of feed
        feed_min_score = feed[1]  # min score to proceed with match
        search_feed_syntax.append(
            "{}{}:[{} TO *]".format(feed_prefix, feed_name, feed_min_score))
        search_feed_syntax.append(
            "{}{}_modload:[{} TO *]".format(
                feed_prefix, feed_name, feed_min_score))

    # try and grab the watchlist if it already exists
    watchlist = cb.select(Watchlist)\
        .where('name:{}'.format(watchlist_name)).first()

    # if it doesn't exist, then create it.
    if watchlist is None:
        create_cb_watchlist(
            cb,
            watchlist_name,
            " OR ".join(search_feed_syntax)
        )

    # otherwise, if it does exist, see if the search contents is
    # good enough (we don't check it perfectly, assuming no-one messes with it)
    else:
        watchlist_search = watchlist.query

        # we look to see if all the items we need to search for
        #   are actually present.
        # AND we look to see if there are any terms the watchlist has that
        #   our search _shouldn't_ be looking for.
        # AND we confirm that there are no logical 'AND'-statements
        #   in the search, it should be all ORs.
        # if that's true, it's good enough to not worry replacing it.
        search_terms_present = [search_item in watchlist_search
                                for search_item in search_feed_syntax]
        terms_in_watchlist = watchlist_search.split(' OR ')
        watchlist_terms_present = [watchlist_item in search_feed_syntax
                                   for watchlist_item in terms_in_watchlist]
        good_enough = \
            all(search_terms_present) and \
            all(watchlist_terms_present) and \
            (" AND " not in watchlist_search)

        if good_enough:
            _logger.debug("Vulnerability Watchlist search correct. Leaving "
                          "it as-is.")

        else:  # the search didn't match, time to replace it.
            create_cb_watchlist(
                cb,
                watchlist_name,
                " OR ".join(search_feed_syntax),
                overwrite=True
            )


def create_cb_watchlist(cb, watchlist_name, search_query_string,
                        watchlist_type='events', overwrite=False):
    """
    Pretty simple here, just creates a watchlist.
    :param cb:  A CbEnterpriseResponseAPI object
    :param watchlist_name:  name of the watchlist
    :param search_query_string:  query to search for in the watchlist
    :param watchlist_type:  defaults to 'events' (a process search in Cb)
    :param overwrite:  delete the existing watchlist (otherwise errors if
                       the watchlist name already exists)
    """
    w = cb.create(
        Watchlist,
        data=dict(name=watchlist_name, index_type=watchlist_type)
    )
    w.query = search_query_string

    # since there isn't just a thing as overwrite, this
    # means, delete the original then plop a new one in it's place.
    if overwrite:
        original_watchlist = cb.select(Watchlist)\
            .where("name:{0}".format(watchlist_name)).first()
        if original_watchlist:
            original_watchlist.delete()

    print(w.search_query)
    # okay, so now try and make the watchlist
    try:
        w.save()
        # restest = w.search().first()
        # print(restest)
        # pass

    except Exception as se:
        raise FletchCriticalError(
            "Could not add vulnerability watchlist: {0}."
            " Error: {1}.".format(watchlist_name, se))

    else:
        _logger.info("Vulnerability Watchlist Updated. New ID is {}".format(
            w.id))
