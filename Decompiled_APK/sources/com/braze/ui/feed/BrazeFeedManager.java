package com.braze.ui.feed;

import com.braze.ui.feed.listeners.BrazeDefaultFeedClickActionListener;
import com.braze.ui.feed.listeners.IFeedClickActionListener;

/* loaded from: classes.dex */
public class BrazeFeedManager {
    private static volatile BrazeFeedManager sInstance;
    private IFeedClickActionListener mCustomFeedClickActionListener;
    private final IFeedClickActionListener mDefaultFeedClickActionListener = new BrazeDefaultFeedClickActionListener();

    public static BrazeFeedManager getInstance() {
        if (sInstance == null) {
            synchronized (BrazeFeedManager.class) {
                try {
                    if (sInstance == null) {
                        sInstance = new BrazeFeedManager();
                    }
                } finally {
                }
            }
        }
        return sInstance;
    }

    public IFeedClickActionListener getFeedCardClickActionListener() {
        IFeedClickActionListener iFeedClickActionListener = this.mCustomFeedClickActionListener;
        return iFeedClickActionListener != null ? iFeedClickActionListener : this.mDefaultFeedClickActionListener;
    }
}
