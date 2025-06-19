package com.braze.ui.widget;

import android.R;
import android.content.Context;
import android.view.ViewTreeObserver;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.braze.Braze;
import com.braze.BrazeInternal;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.enums.BrazeViewBounds;
import com.braze.images.IBrazeImageLoader;
import com.braze.models.cards.Card;
import com.braze.models.cards.d;
import com.braze.support.BrazeLogger;
import com.braze.ui.BrazeDeeplinkHandler;
import com.braze.ui.R$drawable;
import com.braze.ui.R$string;
import com.braze.ui.actions.IAction;
import com.braze.ui.actions.UriAction;
import com.braze.ui.contentcards.BrazeContentCardUtils;
import com.braze.ui.feed.BrazeImageSwitcher;
import com.braze.ui.inappmessage.listeners.a;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public abstract class BaseCardView<T extends Card> extends RelativeLayout {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    protected final Context applicationContext;
    protected T card;

    @NotNull
    private final String classLogTag;

    @NotNull
    protected BrazeConfigurationProvider configurationProvider;
    public BrazeImageSwitcher imageSwitcher;
    private final boolean isUnreadCardVisualIndicatorEnabled;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final UriAction getUriActionForCard(@NotNull Card card) {
            Intrinsics.checkNotNullParameter(card, "card");
            return BrazeContentCardUtils.INSTANCE.getUriActionForCard(card);
        }

        private Companion() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BaseCardView(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        Context applicationContext = context.getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
        this.applicationContext = applicationContext;
        this.classLogTag = BrazeLogger.getBrazeLogTag(getClass());
        BrazeConfigurationProvider configurationProvider = BrazeInternal.INSTANCE.getConfigurationProvider(context);
        this.configurationProvider = configurationProvider;
        this.isUnreadCardVisualIndicatorEnabled = configurationProvider.isNewsfeedVisualIndicatorOn();
    }

    public static final UriAction getUriActionForCard(@NotNull Card card) {
        return Companion.getUriActionForCard(card);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleCardClick$lambda$1(Card card) {
        return "Handling card click for card: " + card;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleCardClick$lambda$2(Card card) {
        return "Card action is non-null. Attempting to perform action on card: " + card.getId();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleCardClick$lambda$3(Card card) {
        return "Executing non uri action for click on card: " + card.getId();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleCardClick$lambda$4(Card card) {
        return "Card action is null. Not performing any click action on card: " + card.getId();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleCardClick$lambda$5(Card card) {
        return "Card click was handled by custom listener on card: " + card.getId();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setCardViewedIndicator$lambda$0() {
        return "imageSwitcher is null. Can't set card viewed indicator.";
    }

    @NotNull
    public final String getClassLogTag() {
        return this.classLogTag;
    }

    public final void handleCardClick(@NotNull Context context, @NotNull Card card, IAction iAction) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(card, "card");
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority = BrazeLogger.Priority.V;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new d(card, 8), 6, (Object) null);
        card.setIndicatorHighlighted(true);
        if (isClickHandled(context, card, iAction)) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new d(card, 12), 7, (Object) null);
            card.logClick();
        } else {
            if (iAction == null) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new d(card, 11), 6, (Object) null);
                return;
            }
            card.logClick();
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new d(card, 9), 6, (Object) null);
            if (iAction instanceof UriAction) {
                BrazeDeeplinkHandler.Companion.getInstance().gotoUri(context, (UriAction) iAction);
            } else {
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new d(card, 10), 7, (Object) null);
                iAction.execute(context);
            }
        }
    }

    public abstract boolean isClickHandled(@NotNull Context context, @NotNull Card card, IAction iAction);

    public final boolean isUnreadIndicatorEnabled() {
        return this.isUnreadCardVisualIndicatorEnabled;
    }

    public final void setCardViewedIndicator(BrazeImageSwitcher brazeImageSwitcher, @NotNull Card card) {
        Intrinsics.checkNotNullParameter(card, "card");
        if (brazeImageSwitcher == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new a(24), 6, (Object) null);
            return;
        }
        Object tag = brazeImageSwitcher.getTag(R$string.com_braze_image_is_read_tag_key);
        if (tag == null) {
            tag = "";
        }
        if (card.isIndicatorHighlighted()) {
            if (tag.equals("icon_read")) {
                return;
            }
            if (brazeImageSwitcher.getReadIcon() != null) {
                brazeImageSwitcher.setImageDrawable(brazeImageSwitcher.getReadIcon());
            } else {
                brazeImageSwitcher.setImageResource(R$drawable.com_braze_content_card_icon_read);
            }
            brazeImageSwitcher.setTag(R$string.com_braze_image_is_read_tag_key, "icon_read");
            return;
        }
        if (tag.equals("icon_unread")) {
            return;
        }
        if (brazeImageSwitcher.getUnReadIcon() != null) {
            brazeImageSwitcher.setImageDrawable(brazeImageSwitcher.getUnReadIcon());
        } else {
            brazeImageSwitcher.setImageResource(R$drawable.com_braze_content_card_icon_unread);
        }
        brazeImageSwitcher.setTag(R$string.com_braze_image_is_read_tag_key, "icon_unread");
    }

    public final void setImageViewToUrl(@NotNull final ImageView imageView, @NotNull String imageUrl, final float f, @NotNull Card card) {
        Intrinsics.checkNotNullParameter(imageView, "imageView");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        Intrinsics.checkNotNullParameter(card, "card");
        if (Intrinsics.b(imageUrl, imageView.getTag(R$string.com_braze_image_resize_tag_key))) {
            return;
        }
        if (f != DefinitionKt.NO_Float_VALUE) {
            ViewTreeObserver viewTreeObserver = imageView.getViewTreeObserver();
            if (viewTreeObserver.isAlive()) {
                viewTreeObserver.addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() { // from class: com.braze.ui.widget.BaseCardView.setImageViewToUrl.1
                    @Override // android.view.ViewTreeObserver.OnPreDrawListener
                    public boolean onPreDraw() {
                        imageView.getViewTreeObserver().removeOnPreDrawListener(this);
                        int width = imageView.getWidth();
                        imageView.setLayoutParams(new RelativeLayout.LayoutParams(width, (int) (width / f)));
                        return true;
                    }
                });
            }
        }
        imageView.setImageResource(R.color.transparent);
        Braze.Companion companion = Braze.Companion;
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        IBrazeImageLoader imageLoader = companion.getInstance(context).getImageLoader();
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        imageLoader.renderUrlIntoCardView(context2, card, imageUrl, imageView, BrazeViewBounds.BASE_CARD_VIEW);
        imageView.setTag(R$string.com_braze_image_resize_tag_key, imageUrl);
    }

    public final void setOptionalTextView(@NotNull TextView view, String str) {
        Intrinsics.checkNotNullParameter(view, "view");
        if (str == null || StringsKt.O(str)) {
            view.setText("");
            view.setVisibility(8);
        } else {
            view.setText(str);
            view.setVisibility(0);
        }
    }
}
