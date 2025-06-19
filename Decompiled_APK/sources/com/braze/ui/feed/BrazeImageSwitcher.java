package com.braze.ui.feed;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.widget.ImageSwitcher;
import com.braze.support.BrazeLogger;
import com.braze.ui.R$styleable;
import com.braze.ui.contentcards.b;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class BrazeImageSwitcher extends ImageSwitcher {
    private Drawable readIcon;
    private Drawable unReadIcon;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BrazeImageSwitcher(@NotNull Context context, AttributeSet attributeSet) {
        Drawable drawable;
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.com_braze_ui_feed_BrazeImageSwitcher);
            Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
            int indexCount = typedArrayObtainStyledAttributes.getIndexCount();
            for (int i = 0; i < indexCount; i++) {
                int index = typedArrayObtainStyledAttributes.getIndex(i);
                if (index == R$styleable.com_braze_ui_feed_BrazeImageSwitcher_brazeFeedCustomReadIcon) {
                    Drawable drawable2 = typedArrayObtainStyledAttributes.getDrawable(index);
                    if (drawable2 != null) {
                        this.readIcon = drawable2;
                    }
                } else if (typedArrayObtainStyledAttributes.getIndex(i) == R$styleable.com_braze_ui_feed_BrazeImageSwitcher_brazeFeedCustomUnReadIcon && (drawable = typedArrayObtainStyledAttributes.getDrawable(index)) != null) {
                    this.unReadIcon = drawable;
                }
            }
            typedArrayObtainStyledAttributes.recycle();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new b(6), 4, (Object) null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _init_$lambda$0() {
        return "Error while checking for custom drawable.";
    }

    public final Drawable getReadIcon() {
        return this.readIcon;
    }

    public final Drawable getUnReadIcon() {
        return this.unReadIcon;
    }

    public final void setReadIcon(Drawable drawable) {
        this.readIcon = drawable;
    }

    public final void setUnReadIcon(Drawable drawable) {
        this.unReadIcon = drawable;
    }
}
