package com.quizlet.quizletandroid.ui.common.views;

import android.content.Context;
import android.util.AttributeSet;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.util.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ContentTextView extends com.quizlet.richtext.ui.e {
    public com.quizlet.qutils.language.a b;
    public com.quizlet.richtext.rendering.c c;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ContentTextView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @NotNull
    public final com.quizlet.richtext.rendering.c getInjectedRichTextRenderer$quizlet_android_app_storeUpload() {
        com.quizlet.richtext.rendering.c cVar = this.c;
        if (cVar != null) {
            return cVar;
        }
        Intrinsics.m("injectedRichTextRenderer");
        throw null;
    }

    @NotNull
    public final com.quizlet.qutils.language.a getLanguageUtil$quizlet_android_app_storeUpload() {
        com.quizlet.qutils.language.a aVar = this.b;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("languageUtil");
        throw null;
    }

    public final void j(com.quizlet.features.infra.models.a data) {
        Intrinsics.checkNotNullParameter(data, "data");
        com.quizlet.qutils.language.a languageUtil$quizlet_android_app_storeUpload = getLanguageUtil$quizlet_android_app_storeUpload();
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        CharSequence charSequenceC = ((f) languageUtil$quizlet_android_app_storeUpload).c(context, data.a, data.b);
        if (data.c) {
            Context context2 = getContext();
            Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
            if (charSequenceC.length() <= 0) {
                charSequenceC = context2.getString(R.string.elipsis);
                Intrinsics.d(charSequenceC);
            }
        }
        String str = data.d;
        h(str != null ? new com.quizlet.richtext.model.a(str) : null, charSequenceC, true);
    }

    public final void setInjectedRichTextRenderer$quizlet_android_app_storeUpload(@NotNull com.quizlet.richtext.rendering.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<set-?>");
        this.c = cVar;
    }

    public final void setLanguageUtil$quizlet_android_app_storeUpload(@NotNull com.quizlet.qutils.language.a aVar) {
        Intrinsics.checkNotNullParameter(aVar, "<set-?>");
        this.b = aVar;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ContentTextView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public ContentTextView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet);
        u uVar = (u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, context.getApplicationContext()));
        this.b = uVar.W();
        this.c = (com.quizlet.richtext.rendering.c) uVar.o0.get();
        setRichTextRenderer(getInjectedRichTextRenderer$quizlet_android_app_storeUpload());
    }
}
