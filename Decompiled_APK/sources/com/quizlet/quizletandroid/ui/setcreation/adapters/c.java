package com.quizlet.quizletandroid.ui.setcreation.adapters;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Filter;
import android.widget.Filterable;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetLanguageSelectionActivity;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends AbstractC1361d0 implements Filterable {
    public final com.quizlet.quizletandroid.util.f a;
    public final String b;
    public List c;
    public final WeakReference d;
    public CharSequence e;

    public c(EditSetLanguageSelectionActivity provider, com.quizlet.quizletandroid.util.f languageUtil, String str) {
        Intrinsics.checkNotNullParameter(provider, "provider");
        Intrinsics.checkNotNullParameter(languageUtil, "languageUtil");
        this.a = languageUtil;
        this.b = str;
        this.c = new ArrayList();
        this.d = new WeakReference(provider);
        List list = this.c;
        ArrayList arrayList = provider.p;
        Intrinsics.checkNotNullExpressionValue(arrayList, "getTopLanguageCodes(...)");
        list.add(arrayList);
        List list2 = this.c;
        ArrayList arrayList2 = provider.q;
        Intrinsics.checkNotNullExpressionValue(arrayList2, "getAllLanguageCodes(...)");
        list2.add(arrayList2);
        this.e = "";
    }

    @Override // android.widget.Filterable
    public final Filter getFilter() {
        return new androidx.cursoradapter.widget.b(this);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return ((List) this.c.get(1)).size() + ((List) this.c.get(0)).size() + (!((List) this.c.get(0)).isEmpty() ? 1 : 0) + (!((List) this.c.get(1)).isEmpty() ? 1 : 0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        if (i == 0) {
            return 1;
        }
        List list = (List) this.c.get(0);
        return (!list.isEmpty() && i == list.size() + 1) ? 1 : 2;
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x00ec  */
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onBindViewHolder(androidx.recyclerview.widget.F0 r9, int r10) {
        /*
            Method dump skipped, instructions count: 271
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setcreation.adapters.c.onBindViewHolder(androidx.recyclerview.widget.F0, int):void");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        if (i != 2) {
            View viewInflate = LayoutInflater.from(parent.getContext()).inflate(R.layout.view_edit_set_language_header, parent, false);
            Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
            return new b(viewInflate);
        }
        int i2 = com.quizlet.quizletandroid.ui.setcreation.viewholders.a.c;
        View viewInflate2 = LayoutInflater.from(parent.getContext()).inflate(R.layout.view_edit_set_language_option, parent, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate2, "inflate(...)");
        return new com.quizlet.quizletandroid.ui.setcreation.viewholders.a(viewInflate2, new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 16));
    }
}
