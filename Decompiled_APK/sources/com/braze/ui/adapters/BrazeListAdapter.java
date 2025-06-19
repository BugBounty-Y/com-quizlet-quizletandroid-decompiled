package com.braze.ui.adapters;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import androidx.annotation.NonNull;
import com.braze.models.cards.CaptionedImageCard;
import com.braze.models.cards.Card;
import com.braze.models.cards.ImageOnlyCard;
import com.braze.models.cards.ShortNewsCard;
import com.braze.models.cards.TextAnnouncementCard;
import com.braze.support.BrazeLogger;
import com.braze.ui.feed.view.BaseFeedCardView;
import com.braze.ui.widget.CaptionedImageCardView;
import com.braze.ui.widget.DefaultCardView;
import com.braze.ui.widget.ImageOnlyCardView;
import com.braze.ui.widget.ShortNewsCardView;
import com.braze.ui.widget.TextAnnouncementCardView;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/* loaded from: classes.dex */
public class BrazeListAdapter extends ArrayAdapter<Card> {
    private static final String TAG = BrazeLogger.getBrazeLogTag((Class<?>) BrazeListAdapter.class);
    private final Set<String> mCardIdImpressions;
    private final Context mContext;

    public BrazeListAdapter(Context context, int i, List<Card> list) {
        super(context, i, list);
        this.mContext = context;
        this.mCardIdImpressions = new HashSet();
    }

    private void logCardImpression(Card card) {
        String id = card.getId();
        if (this.mCardIdImpressions.contains(id)) {
            BrazeLogger.v(TAG, "Already counted impression for card " + id);
        } else {
            this.mCardIdImpressions.add(id);
            card.logImpression();
            BrazeLogger.v(TAG, "Logged impression for card " + id);
        }
        if (card.getViewed()) {
            return;
        }
        card.setViewed(true);
    }

    public void batchSetCardsToRead(int i, int i2) {
        if (getCount() == 0) {
            BrazeLogger.d(TAG, "mAdapter is empty in setting some cards to viewed.");
            return;
        }
        int iMin = Math.min(getCount(), i2);
        for (int iMax = Math.max(0, i); iMax < iMin; iMax++) {
            Card card = (Card) getItem(iMax);
            if (card == null) {
                BrazeLogger.d(TAG, "Card was null in setting some cards to viewed.");
                return;
            } else {
                if (!card.isIndicatorHighlighted()) {
                    card.setIndicatorHighlighted(true);
                }
            }
        }
    }

    @Override // android.widget.BaseAdapter, android.widget.Adapter
    public int getItemViewType(int i) {
        Card card = (Card) getItem(i);
        if (card instanceof ImageOnlyCard) {
            return 1;
        }
        if (card instanceof CaptionedImageCard) {
            return 2;
        }
        if (card instanceof ShortNewsCard) {
            return 3;
        }
        return card instanceof TextAnnouncementCard ? 4 : 0;
    }

    @Override // android.widget.ArrayAdapter, android.widget.Adapter
    @NonNull
    public View getView(int i, View view, @NonNull ViewGroup viewGroup) {
        BaseFeedCardView imageOnlyCardView;
        Card card = (Card) getItem(i);
        if (view == null) {
            imageOnlyCardView = card instanceof ImageOnlyCard ? new ImageOnlyCardView(this.mContext) : card instanceof CaptionedImageCard ? new CaptionedImageCardView(this.mContext) : card instanceof ShortNewsCard ? new ShortNewsCardView(this.mContext) : card instanceof TextAnnouncementCard ? new TextAnnouncementCardView(this.mContext) : new DefaultCardView(this.mContext);
        } else {
            BrazeLogger.v(TAG, "Reusing convertView for rendering of item " + i);
            imageOnlyCardView = (BaseFeedCardView) view;
        }
        BrazeLogger.v(TAG, "Using view of type: " + imageOnlyCardView.getClass().getName() + " for card at position " + i + ": " + card.toString());
        imageOnlyCardView.setCard(card);
        logCardImpression(card);
        return imageOnlyCardView;
    }

    @Override // android.widget.BaseAdapter, android.widget.Adapter
    public int getViewTypeCount() {
        return 5;
    }

    public synchronized void replaceFeed(List<Card> list) {
        int i = 0;
        setNotifyOnChange(false);
        if (list == null) {
            clear();
            notifyDataSetChanged();
            return;
        }
        BrazeLogger.d(TAG, "Replacing existing feed of " + getCount() + " cards with new feed containing " + list.size() + " cards.");
        int size = list.size();
        int i2 = 0;
        while (i < getCount()) {
            Card card = (Card) getItem(i);
            Card card2 = i2 < size ? list.get(i2) : null;
            if (card2 == null || !card2.equals(card)) {
                remove(card);
            } else {
                i++;
                i2++;
            }
        }
        super.addAll(list.subList(i2, size));
        notifyDataSetChanged();
    }

    public void resetCardImpressionTracker() {
        this.mCardIdImpressions.clear();
    }

    @Override // android.widget.ArrayAdapter
    public synchronized void add(Card card) {
        super.add((BrazeListAdapter) card);
    }
}
