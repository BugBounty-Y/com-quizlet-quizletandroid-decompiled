package com.braze.ui.feed.listeners;

import android.content.Context;
import com.braze.models.cards.Card;
import com.braze.ui.actions.IAction;

/* loaded from: classes.dex */
public class BrazeDefaultFeedClickActionListener implements IFeedClickActionListener {
    @Override // com.braze.ui.feed.listeners.IFeedClickActionListener
    public boolean onFeedCardClicked(Context context, Card card, IAction iAction) {
        return false;
    }
}
