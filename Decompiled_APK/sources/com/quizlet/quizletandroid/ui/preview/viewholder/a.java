package com.quizlet.quizletandroid.ui.preview.viewholder;

import android.view.View;
import com.quizlet.baserecyclerview.c;
import com.quizlet.quizletandroid.databinding.j0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class a extends c {
    public static final /* synthetic */ int e = 0;
    public final com.quizlet.qutils.image.loading.a d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(View view, com.quizlet.qutils.image.loading.a imageLoader) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        this.d = imageLoader;
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        j0 j0VarA = j0.a(this.a);
        Intrinsics.checkNotNullExpressionValue(j0VarA, "bind(...)");
        return j0VarA;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(com.quizlet.quizletandroid.ui.preview.dataclass.c previewTerm) {
        Intrinsics.checkNotNullParameter(previewTerm, "previewTerm");
        ((j0) e()).e.setText(previewTerm.b);
        String str = previewTerm.c;
        if (str == null || StringsKt.O(str)) {
            ((j0) e()).b.setVisibility(8);
        } else {
            ((j0) e()).b.setVisibility(0);
            ((j0) e()).b.setText(str);
        }
        String str2 = previewTerm.d;
        if (str2 == null) {
            ((j0) e()).d.setVisibility(8);
        } else {
            ((j0) e()).d.setVisibility(0);
            ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) this.d).a(this.b).p(str2).o(((j0) e()).c);
        }
    }
}
