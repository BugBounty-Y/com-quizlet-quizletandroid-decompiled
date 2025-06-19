package com.quizlet.diagrams;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.subjects.j;
import java.util.List;
import kotlin.Pair;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e extends AbstractC1361d0 {
    public List a;
    public final com.quizlet.qutils.image.loading.a b;
    public long c;
    public final j d;
    public final j e;
    public final j f;

    public e(K terms, com.quizlet.qutils.image.loading.a imageLoader) {
        Intrinsics.checkNotNullParameter(terms, "terms");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        this.a = terms;
        this.b = imageLoader;
        j jVar = new j();
        Intrinsics.checkNotNullExpressionValue(jVar, "create(...)");
        this.d = jVar;
        j jVar2 = new j();
        Intrinsics.checkNotNullExpressionValue(jVar2, "create(...)");
        this.e = jVar2;
        j jVar3 = new j();
        Intrinsics.checkNotNullExpressionValue(jVar3, "create(...)");
        this.f = jVar3;
        setHasStableIds(true);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.a.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final long getItemId(int i) {
        return ((DBTerm) ((Pair) this.a.get(i)).a).getLocalId();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:21:0x010e  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0110  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x012f  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0131  */
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onBindViewHolder(androidx.recyclerview.widget.F0 r17, int r18) throws android.content.res.Resources.NotFoundException {
        /*
            Method dump skipped, instructions count: 322
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.diagrams.e.onBindViewHolder(androidx.recyclerview.widget.F0, int):void");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View viewInflate = LayoutInflater.from(parent.getContext()).inflate(R.layout.diagram_listitem_detailcard, parent, false);
        Intrinsics.d(viewInflate);
        return new d(viewInflate, this.b);
    }
}
