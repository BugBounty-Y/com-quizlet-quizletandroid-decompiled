package com.skydoves.balloon;

import android.content.Context;
import android.graphics.Typeface;
import android.text.method.MovementMethod;
import com.skydoves.balloon.annotations.Dp;
import com.skydoves.balloon.annotations.Sp;
import com.skydoves.balloon.extensions.ContextExtensionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class TextForm {
    private final boolean enableAutoSized;
    private final boolean includeFontPadding;
    private final float maxAutoSizeTextSize;
    private final float minAutoSizeTextSize;
    private final MovementMethod movementMethod;

    @NotNull
    private final CharSequence text;
    private final int textColor;
    private final int textGravity;
    private final boolean textIsHtml;
    private final Float textLetterSpacing;
    private final Float textLineSpacing;

    @Sp
    private final float textSize;
    private final int textStyle;
    private final Typeface textTypeface;

    @TextFormDsl
    @Metadata
    public static final class Builder {

        @NotNull
        private final Context context;
        private boolean enableAutoSized;
        private boolean includeFontPadding;
        private float maxAutoSizeTextSize;
        private float minAutoSizeTextSize;
        private MovementMethod movementMethod;

        @NotNull
        private CharSequence text;
        private int textColor;
        private int textGravity;
        private boolean textIsHtml;
        private Float textLetterSpacing;
        private Float textLineSpacing;

        @Sp
        private float textSize;
        private int textTypeface;
        private Typeface textTypefaceObject;

        public Builder(@NotNull Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            this.context = context;
            this.text = "";
            this.textSize = 12.0f;
            this.enableAutoSized = true;
            this.minAutoSizeTextSize = 12.0f;
            this.maxAutoSizeTextSize = 12.0f + 1;
            this.textColor = -1;
            this.includeFontPadding = true;
            this.textGravity = 17;
        }

        @NotNull
        public final TextForm build() {
            return new TextForm(this, null);
        }

        @NotNull
        public final Context getContext() {
            return this.context;
        }

        public final boolean getEnableAutoSized() {
            return this.enableAutoSized;
        }

        public final boolean getIncludeFontPadding() {
            return this.includeFontPadding;
        }

        public final float getMaxAutoSizeTextSize() {
            return this.maxAutoSizeTextSize;
        }

        public final float getMinAutoSizeTextSize() {
            return this.minAutoSizeTextSize;
        }

        public final MovementMethod getMovementMethod() {
            return this.movementMethod;
        }

        @NotNull
        public final CharSequence getText() {
            return this.text;
        }

        public final int getTextColor() {
            return this.textColor;
        }

        public final int getTextGravity() {
            return this.textGravity;
        }

        public final boolean getTextIsHtml() {
            return this.textIsHtml;
        }

        public final Float getTextLetterSpacing() {
            return this.textLetterSpacing;
        }

        public final Float getTextLineSpacing() {
            return this.textLineSpacing;
        }

        public final float getTextSize() {
            return this.textSize;
        }

        public final int getTextTypeface() {
            return this.textTypeface;
        }

        public final Typeface getTextTypefaceObject() {
            return this.textTypefaceObject;
        }

        /* renamed from: setEnableAutoSized, reason: collision with other method in class */
        public final /* synthetic */ void m129setEnableAutoSized(boolean z) {
            this.enableAutoSized = z;
        }

        /* renamed from: setIncludeFontPadding, reason: collision with other method in class */
        public final /* synthetic */ void m130setIncludeFontPadding(boolean z) {
            this.includeFontPadding = z;
        }

        /* renamed from: setMaxAutoSizeTextSize, reason: collision with other method in class */
        public final /* synthetic */ void m131setMaxAutoSizeTextSize(float f) {
            this.maxAutoSizeTextSize = f;
        }

        /* renamed from: setMinAutoSizeTextSize, reason: collision with other method in class */
        public final /* synthetic */ void m132setMinAutoSizeTextSize(float f) {
            this.minAutoSizeTextSize = f;
        }

        /* renamed from: setMovementMethod, reason: collision with other method in class */
        public final /* synthetic */ void m133setMovementMethod(MovementMethod movementMethod) {
            this.movementMethod = movementMethod;
        }

        /* renamed from: setText, reason: collision with other method in class */
        public final /* synthetic */ void m134setText(CharSequence charSequence) {
            Intrinsics.checkNotNullParameter(charSequence, "<set-?>");
            this.text = charSequence;
        }

        /* renamed from: setTextColor, reason: collision with other method in class */
        public final /* synthetic */ void m135setTextColor(int i) {
            this.textColor = i;
        }

        @NotNull
        public final Builder setTextColorResource(int i) {
            this.textColor = ContextExtensionKt.contextColor(this.context, i);
            return this;
        }

        /* renamed from: setTextGravity, reason: collision with other method in class */
        public final /* synthetic */ void m136setTextGravity(int i) {
            this.textGravity = i;
        }

        /* renamed from: setTextIsHtml, reason: collision with other method in class */
        public final /* synthetic */ void m137setTextIsHtml(boolean z) {
            this.textIsHtml = z;
        }

        /* renamed from: setTextLetterSpacing, reason: collision with other method in class */
        public final /* synthetic */ void m138setTextLetterSpacing(Float f) {
            this.textLetterSpacing = f;
        }

        @NotNull
        public final Builder setTextLetterSpacingResource(int i) {
            this.textLetterSpacing = Float.valueOf(ContextExtensionKt.dimen(this.context, i));
            return this;
        }

        /* renamed from: setTextLineSpacing, reason: collision with other method in class */
        public final /* synthetic */ void m139setTextLineSpacing(Float f) {
            this.textLineSpacing = f;
        }

        @NotNull
        public final Builder setTextLineSpacingResource(int i) {
            this.textLineSpacing = Float.valueOf(ContextExtensionKt.dimen(this.context, i));
            return this;
        }

        @NotNull
        public final Builder setTextResource(int i) {
            this.text = this.context.getString(i);
            return this;
        }

        /* renamed from: setTextSize, reason: collision with other method in class */
        public final /* synthetic */ void m140setTextSize(float f) {
            this.textSize = f;
        }

        @NotNull
        public final Builder setTextSizeResource(int i) {
            Context context = this.context;
            this.textSize = ContextExtensionKt.px2Sp(context, ContextExtensionKt.dimen(context, i));
            return this;
        }

        /* renamed from: setTextTypeface, reason: collision with other method in class */
        public final /* synthetic */ void m141setTextTypeface(int i) {
            this.textTypeface = i;
        }

        public final /* synthetic */ void setTextTypefaceObject(Typeface typeface) {
            this.textTypefaceObject = typeface;
        }

        @NotNull
        public final Builder setEnableAutoSized(boolean z) {
            this.enableAutoSized = z;
            return this;
        }

        @NotNull
        public final Builder setIncludeFontPadding(boolean z) {
            this.includeFontPadding = z;
            return this;
        }

        @NotNull
        public final Builder setMaxAutoSizeTextSize(@Sp float f) {
            this.maxAutoSizeTextSize = f;
            return this;
        }

        @NotNull
        public final Builder setMinAutoSizeTextSize(@Sp float f) {
            this.minAutoSizeTextSize = f;
            return this;
        }

        @NotNull
        public final Builder setMovementMethod(@NotNull MovementMethod value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.movementMethod = value;
            return this;
        }

        @NotNull
        public final Builder setText(@NotNull CharSequence value) {
            Intrinsics.checkNotNullParameter(value, "value");
            this.text = value;
            return this;
        }

        @NotNull
        public final Builder setTextColor(int i) {
            this.textColor = i;
            return this;
        }

        @NotNull
        public final Builder setTextGravity(int i) {
            this.textGravity = i;
            return this;
        }

        @NotNull
        public final Builder setTextIsHtml(boolean z) {
            this.textIsHtml = z;
            return this;
        }

        @NotNull
        public final Builder setTextLetterSpacing(@Dp Float f) {
            this.textLetterSpacing = f;
            return this;
        }

        @NotNull
        public final Builder setTextLineSpacing(@Dp Float f) {
            this.textLineSpacing = f;
            return this;
        }

        @NotNull
        public final Builder setTextSize(@Sp float f) {
            this.textSize = f;
            return this;
        }

        @NotNull
        public final Builder setTextTypeface(int i) {
            this.textTypeface = i;
            return this;
        }

        @NotNull
        public final Builder setTextTypeface(Typeface typeface) {
            this.textTypefaceObject = typeface;
            return this;
        }
    }

    public /* synthetic */ TextForm(Builder builder, DefaultConstructorMarker defaultConstructorMarker) {
        this(builder);
    }

    public final boolean getEnableAutoSized() {
        return this.enableAutoSized;
    }

    public final boolean getIncludeFontPadding() {
        return this.includeFontPadding;
    }

    public final float getMaxAutoSizeTextSize() {
        return this.maxAutoSizeTextSize;
    }

    public final float getMinAutoSizeTextSize() {
        return this.minAutoSizeTextSize;
    }

    public final MovementMethod getMovementMethod() {
        return this.movementMethod;
    }

    @NotNull
    public final CharSequence getText() {
        return this.text;
    }

    public final int getTextColor() {
        return this.textColor;
    }

    public final int getTextGravity() {
        return this.textGravity;
    }

    public final boolean getTextIsHtml() {
        return this.textIsHtml;
    }

    public final Float getTextLetterSpacing() {
        return this.textLetterSpacing;
    }

    public final Float getTextLineSpacing() {
        return this.textLineSpacing;
    }

    public final float getTextSize() {
        return this.textSize;
    }

    public final int getTextStyle() {
        return this.textStyle;
    }

    public final Typeface getTextTypeface() {
        return this.textTypeface;
    }

    private TextForm(Builder builder) {
        this.text = builder.getText();
        this.textSize = builder.getTextSize();
        this.enableAutoSized = builder.getEnableAutoSized();
        this.minAutoSizeTextSize = builder.getMinAutoSizeTextSize();
        this.maxAutoSizeTextSize = builder.getMaxAutoSizeTextSize();
        this.textColor = builder.getTextColor();
        this.textIsHtml = builder.getTextIsHtml();
        this.movementMethod = builder.getMovementMethod();
        this.textStyle = builder.getTextTypeface();
        this.textTypeface = builder.getTextTypefaceObject();
        this.textLineSpacing = builder.getTextLineSpacing();
        this.includeFontPadding = builder.getIncludeFontPadding();
        this.textLetterSpacing = builder.getTextLetterSpacing();
        this.textGravity = builder.getTextGravity();
    }
}
