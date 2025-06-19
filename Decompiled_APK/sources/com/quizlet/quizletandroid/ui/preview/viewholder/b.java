package com.quizlet.quizletandroid.ui.preview.viewholder;

import android.content.Context;
import android.view.View;
import androidx.recyclerview.widget.LinearLayoutManager;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.v;
import com.quizlet.baserecyclerview.c;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.h0;
import com.quizlet.quizletandroid.ui.common.views.VerticalFadingEdgeRecyclerView;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends c implements com.quizlet.baserecyclerview.decoration.b {
    public static final /* synthetic */ int e = 0;
    public final v d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(View view, com.quizlet.qutils.image.loading.a imageLoader) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        v vVar = new v(imageLoader);
        this.d = vVar;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this.a.getContext());
        ((h0) e()).b.setAdapter(vVar);
        ((h0) e()).b.setLayoutManager(linearLayoutManager);
        VerticalFadingEdgeRecyclerView searchSetPreviewTermRecyclerView = ((h0) e()).b;
        Intrinsics.checkNotNullExpressionValue(searchSetPreviewTermRecyclerView, "searchSetPreviewTermRecyclerView");
        Context context = this.b;
        com.quizlet.baserecyclerview.decoration.c cVar = new com.quizlet.baserecyclerview.decoration.c(context, 1, 0, this);
        Intrinsics.checkNotNullExpressionValue(context, "<get-context>(...)");
        cVar.a.setColor(com.quizlet.themes.extensions.a.a(context, R.attr.RefColorGray400));
        searchSetPreviewTermRecyclerView.i(cVar);
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        h0 h0VarA = h0.a(this.a);
        Intrinsics.checkNotNullExpressionValue(h0VarA, "bind(...)");
        return h0VarA;
    }

    @Override // com.quizlet.baserecyclerview.c
    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final void c(com.quizlet.quizletandroid.ui.preview.dataclass.a previewData) {
        Intrinsics.checkNotNullParameter(previewData, "previewData");
        ((h0) e()).d.setText(previewData.b);
        ((h0) e()).c.setText(previewData.c + " terms");
        v vVar = this.d;
        vVar.getClass();
        ArrayList terms = previewData.d;
        Intrinsics.checkNotNullParameter(terms, "terms");
        ArrayList arrayList = (ArrayList) vVar.c;
        arrayList.clear();
        arrayList.addAll(terms);
        vVar.notifyDataSetChanged();
    }

    @Override // com.quizlet.baserecyclerview.decoration.b
    public final boolean z(int i) {
        return i != this.d.getItemCount() - 1;
    }
}
