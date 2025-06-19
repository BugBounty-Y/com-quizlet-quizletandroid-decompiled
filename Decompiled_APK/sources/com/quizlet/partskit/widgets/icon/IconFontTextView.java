package com.quizlet.partskit.widgets.icon;

import android.content.Context;
import android.content.res.Resources;
import android.util.AttributeSet;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.appcompat.widget.C0108s;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.quizletandroid.u;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import timber.log.c;

@Metadata
/* loaded from: classes3.dex */
public class IconFontTextView extends C0108s {
    public final b e;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public IconFontTextView(@NotNull Context context) {
        this(context, null, 6, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        Intrinsics.checkNotNullParameter(info, "info");
        super.onInitializeAccessibilityNodeInfo(info);
        info.setCheckable(false);
    }

    public final void setIcon(@NotNull String iconName) {
        Intrinsics.checkNotNullParameter(iconName, "iconName");
        setText(this.e.a(iconName));
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public IconFontTextView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ IconFontTextView(Context context, AttributeSet attributeSet, int i, int i2) {
        this(context, (i & 2) != 0 ? null : attributeSet, 0);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public IconFontTextView(Context context, AttributeSet attributeSet, int i) throws Resources.NotFoundException {
        super(context, attributeSet, 0);
        Intrinsics.checkNotNullParameter(context, "context");
        this.e = new b(((u) ((a) K6.b(a.class, context.getApplicationContext()))).q());
        String attributeValue = attributeSet != null ? attributeSet.getAttributeValue("http://schemas.android.com/apk/res-auto", "iconName") : null;
        if (attributeValue != null) {
            setIcon(attributeValue);
        }
        if (getContentDescription() == null) {
            try {
                c.a.e(new RuntimeException("Missing content description for icon '" + attributeValue + "', id is " + getResources().getResourceEntryName(getId())));
            } catch (Resources.NotFoundException unused) {
                c.a.e(new RuntimeException(android.support.v4.media.session.a.B("Missing content description for icon '", attributeValue, "' with no ID set")));
            }
        }
    }
}
