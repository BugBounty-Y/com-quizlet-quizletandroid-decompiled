package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.view.LayoutInflater;
import android.view.ViewGroup;
import androidx.compose.ui.platform.C0960p;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p extends AbstractC1361d0 {
    public final ArrayList a;
    public final C0960p b;
    public final boolean c;

    public p(ArrayList permissions, C0960p callback, boolean z) {
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        Intrinsics.checkNotNullParameter(callback, "callback");
        this.a = permissions;
        this.b = callback;
        this.c = z;
        setHasStableIds(true);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.a.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final long getItemId(int i) {
        return ((n) this.a.get(i)).hashCode();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        o holder = (o) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        n permission = (n) this.a.get(i);
        holder.getClass();
        Intrinsics.checkNotNullParameter(permission, "permission");
        com.onetrust.otpublishers.headless.databinding.b bVar = holder.a;
        ((QTextView) bVar.d).setText(permission.a);
        ((IconFontTextView) bVar.c).setVisibility(permission.c ? 0 : 8);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        com.onetrust.otpublishers.headless.databinding.b bVarB = com.onetrust.otpublishers.headless.databinding.b.b(LayoutInflater.from(parent.getContext()).inflate(R.layout.view_edit_set_language_option, parent, false));
        Intrinsics.checkNotNullExpressionValue(bVarB, "inflate(...)");
        return new o(bVarB, this.b, this.a, this.c);
    }
}
