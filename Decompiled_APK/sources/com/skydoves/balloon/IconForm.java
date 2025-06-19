package com.skydoves.balloon;

import android.content.Context;
import android.graphics.drawable.Drawable;
import com.quizlet.data.model.AbstractC4178x;
import com.skydoves.balloon.extensions.ContextExtensionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class IconForm {
    private final Drawable drawable;
    private Integer drawableRes;
    private final int iconColor;

    @NotNull
    private final CharSequence iconContentDescription;

    @NotNull
    private final IconGravity iconGravity;
    private final int iconHeight;
    private final int iconSpace;
    private final int iconWidth;

    @Metadata
    @IconFormDsl
    public static final class Builder {

        @NotNull
        private final Context context;
        private Drawable drawable;
        private Integer drawableRes;
        private int iconColor;

        @NotNull
        private CharSequence iconContentDescription;

        @NotNull
        private IconGravity iconGravity;
        private int iconHeight;
        private int iconSpace;
        private int iconWidth;

        public Builder(@NotNull Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            this.context = context;
            this.iconGravity = IconGravity.START;
            float f = 28;
            this.iconWidth = AbstractC4178x.a(f, 1);
            this.iconHeight = AbstractC4178x.a(f, 1);
            this.iconSpace = AbstractC4178x.a(8, 1);
            this.iconColor = -1;
            this.iconContentDescription = "";
        }

        @NotNull
        public final IconForm build() {
            return new IconForm(this, null);
        }

        @NotNull
        public final Context getContext() {
            return this.context;
        }

        public final Drawable getDrawable() {
            return this.drawable;
        }

        public final Integer getDrawableRes() {
            return this.drawableRes;
        }

        public final int getIconColor() {
            return this.iconColor;
        }

        @NotNull
        public final CharSequence getIconContentDescription() {
            return this.iconContentDescription;
        }

        @NotNull
        public final IconGravity getIconGravity() {
            return this.iconGravity;
        }

        public final int getIconHeight() {
            return this.iconHeight;
        }

        public final int getIconSpace() {
            return this.iconSpace;
        }

        public final int getIconWidth() {
            return this.iconWidth;
        }

        /* renamed from: setDrawable, reason: collision with other method in class */
        public final /* synthetic */ void m123setDrawable(Drawable drawable) {
            this.drawable = drawable;
        }

        @NotNull
        public final Builder setDrawableGravity(@NotNull IconGravity value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.iconGravity = value;
            return this;
        }

        public final /* synthetic */ void setDrawableRes(Integer num) {
            this.drawableRes = num;
        }

        @NotNull
        public final Builder setDrawableResource(int i) {
            this.drawableRes = Integer.valueOf(i);
            return this;
        }

        /* renamed from: setIconColor, reason: collision with other method in class */
        public final /* synthetic */ void m124setIconColor(int i) {
            this.iconColor = i;
        }

        @NotNull
        public final Builder setIconColorResource(int i) {
            this.iconColor = ContextExtensionKt.contextColor(this.context, i);
            return this;
        }

        /* renamed from: setIconContentDescription, reason: collision with other method in class */
        public final /* synthetic */ void m125setIconContentDescription(CharSequence charSequence) {
            Intrinsics.checkNotNullParameter(charSequence, "<set-?>");
            this.iconContentDescription = charSequence;
        }

        @NotNull
        public final Builder setIconContentDescriptionResource(int i) {
            this.iconContentDescription = this.context.getString(i);
            return this;
        }

        public final /* synthetic */ void setIconGravity(IconGravity iconGravity) {
            Intrinsics.checkNotNullParameter(iconGravity, "<set-?>");
            this.iconGravity = iconGravity;
        }

        /* renamed from: setIconHeight, reason: collision with other method in class */
        public final /* synthetic */ void m126setIconHeight(int i) {
            this.iconHeight = i;
        }

        @NotNull
        public final Builder setIconSize(int i) {
            setIconWidth(i);
            setIconHeight(i);
            return this;
        }

        /* renamed from: setIconSpace, reason: collision with other method in class */
        public final /* synthetic */ void m127setIconSpace(int i) {
            this.iconSpace = i;
        }

        /* renamed from: setIconWidth, reason: collision with other method in class */
        public final /* synthetic */ void m128setIconWidth(int i) {
            this.iconWidth = i;
        }

        @NotNull
        public final Builder setDrawable(Drawable drawable) {
            this.drawable = drawable;
            return this;
        }

        @NotNull
        public final Builder setIconColor(int i) {
            this.iconColor = i;
            return this;
        }

        @NotNull
        public final Builder setIconContentDescription(@NotNull CharSequence value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.iconContentDescription = value;
            return this;
        }

        @NotNull
        public final Builder setIconHeight(int i) {
            this.iconHeight = i;
            return this;
        }

        @NotNull
        public final Builder setIconSpace(int i) {
            this.iconSpace = i;
            return this;
        }

        @NotNull
        public final Builder setIconWidth(int i) {
            this.iconWidth = i;
            return this;
        }
    }

    public /* synthetic */ IconForm(Builder builder, DefaultConstructorMarker defaultConstructorMarker) {
        this(builder);
    }

    public final Drawable getDrawable() {
        return this.drawable;
    }

    public final Integer getDrawableRes() {
        return this.drawableRes;
    }

    public final int getIconColor() {
        return this.iconColor;
    }

    @NotNull
    public final CharSequence getIconContentDescription() {
        return this.iconContentDescription;
    }

    @NotNull
    public final IconGravity getIconGravity() {
        return this.iconGravity;
    }

    public final int getIconHeight() {
        return this.iconHeight;
    }

    public final int getIconSpace() {
        return this.iconSpace;
    }

    public final int getIconWidth() {
        return this.iconWidth;
    }

    public final void setDrawableRes(Integer num) {
        this.drawableRes = num;
    }

    private IconForm(Builder builder) {
        this.drawable = builder.getDrawable();
        this.drawableRes = builder.getDrawableRes();
        this.iconGravity = builder.getIconGravity();
        this.iconWidth = builder.getIconWidth();
        this.iconHeight = builder.getIconHeight();
        this.iconSpace = builder.getIconSpace();
        this.iconColor = builder.getIconColor();
        this.iconContentDescription = builder.getIconContentDescription();
    }
}
