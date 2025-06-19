package com.onetrust.otpublishers.headless.UI.adapter;

import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.recyclerview.widget.C1364f;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.V;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3689o4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3697p4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class K extends V {
    public final com.onetrust.otpublishers.headless.UI.DataModels.l c;
    public final OTConfiguration d;
    public final boolean e;
    public final com.onetrust.otpublishers.headless.UI.fragment.E f;
    public final com.onetrust.otpublishers.headless.UI.fragment.F g;
    public LayoutInflater h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(com.onetrust.otpublishers.headless.UI.DataModels.l vendorListData, OTConfiguration oTConfiguration, boolean z, com.onetrust.otpublishers.headless.UI.fragment.E onItemToggleCheckedChange, com.onetrust.otpublishers.headless.UI.fragment.F onItemClicked) {
        super(new s(1));
        Intrinsics.checkNotNullParameter(vendorListData, "vendorListData");
        Intrinsics.checkNotNullParameter(onItemToggleCheckedChange, "onItemToggleCheckedChange");
        Intrinsics.checkNotNullParameter(onItemClicked, "onItemClicked");
        this.c = vendorListData;
        this.d = oTConfiguration;
        this.e = z;
        this.f = onItemToggleCheckedChange;
        this.g = onItemClicked;
    }

    @Override // androidx.recyclerview.widget.V, androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return super.getItemCount() + 1;
    }

    @Override // androidx.recyclerview.widget.V, androidx.recyclerview.widget.AbstractC1361d0
    public final void onAttachedToRecyclerView(RecyclerView recyclerView) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        super.onAttachedToRecyclerView(recyclerView);
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(recyclerView.getContext());
        Intrinsics.checkNotNullExpressionValue(layoutInflaterFrom, "from(recyclerView.context)");
        this.h = layoutInflaterFrom;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) throws Resources.NotFoundException, NumberFormatException {
        J holder = (J) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        List currentList = ((C1364f) this.b).f;
        Intrinsics.checkNotNullExpressionValue(currentList, "currentList");
        com.onetrust.otpublishers.headless.UI.DataModels.j jVar = (com.onetrust.otpublishers.headless.UI.DataModels.j) CollectionsKt.O(i, currentList);
        boolean z = i == getItemCount() - 1;
        com.onetrust.otpublishers.headless.databinding.d dVar = holder.a;
        RelativeLayout vlItems = (RelativeLayout) dVar.c;
        Intrinsics.checkNotNullExpressionValue(vlItems, "vlItems");
        vlItems.setVisibility(!z ? 0 : 8);
        View view3 = (View) dVar.h;
        Intrinsics.checkNotNullExpressionValue(view3, "view3");
        view3.setVisibility(!z ? 0 : 8);
        SwitchCompat switchButton = (SwitchCompat) dVar.e;
        Intrinsics.checkNotNullExpressionValue(switchButton, "switchButton");
        switchButton.setVisibility((z || !holder.d) ? 8 : 0);
        TextView viewPoweredByLogo = (TextView) dVar.g;
        Intrinsics.checkNotNullExpressionValue(viewPoweredByLogo, "viewPoweredByLogo");
        viewPoweredByLogo.setVisibility(z ? 0 : 8);
        com.onetrust.otpublishers.headless.UI.DataModels.l lVar = holder.b;
        if (z || jVar == null) {
            com.onetrust.otpublishers.headless.UI.UIProperty.e eVar = lVar.v;
            if (eVar == null || !eVar.i) {
                Intrinsics.checkNotNullExpressionValue(viewPoweredByLogo, "");
                viewPoweredByLogo.setVisibility(8);
                return;
            }
            androidx.navigation.internal.m mVar = eVar.l;
            Intrinsics.checkNotNullExpressionValue(mVar, "vendorListData.otPCUIPro…leDescriptionTextProperty");
            viewPoweredByLogo.setTextColor(Color.parseColor((String) mVar.b));
            Intrinsics.checkNotNullExpressionValue(viewPoweredByLogo, "");
            AbstractC3689o4.g(viewPoweredByLogo, (String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d);
            com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
            Intrinsics.checkNotNullExpressionValue(kVar, "descriptionTextProperty.fontProperty");
            AbstractC3689o4.c(viewPoweredByLogo, kVar, holder.c);
            viewPoweredByLogo.setTextAlignment(P.k(viewPoweredByLogo.getContext()) ? 6 : 4);
            return;
        }
        ImageView gvShowMore = (ImageView) dVar.d;
        Intrinsics.checkNotNullExpressionValue(gvShowMore, "gvShowMore");
        gvShowMore.setVisibility(0);
        TextView vendorName = (TextView) dVar.f;
        vendorName.setText(jVar.b);
        vendorName.setLabelFor(R.id.switchButton);
        RelativeLayout relativeLayout = (RelativeLayout) dVar.c;
        relativeLayout.setOnClickListener(null);
        relativeLayout.setOnClickListener(new com.braze.ui.inappmessage.views.a(11, holder, jVar));
        androidx.navigation.internal.m mVar2 = lVar.k;
        Intrinsics.checkNotNullExpressionValue(vendorName, "vendorName");
        AbstractC3689o4.a(vendorName, mVar2, null, holder.c, false, 2);
        Intrinsics.checkNotNullExpressionValue(gvShowMore, "gvShowMore");
        Intrinsics.checkNotNullParameter(gvShowMore, "<this>");
        String str = lVar.w;
        if (str != null && str.length() != 0) {
            gvShowMore.setColorFilter(Color.parseColor(str), PorterDuff.Mode.SRC_IN);
        }
        Intrinsics.checkNotNullExpressionValue(view3, "view3");
        AbstractC3697p4.d(view3, lVar.e);
        switchButton.setOnCheckedChangeListener(null);
        int iOrdinal = jVar.c.ordinal();
        if (iOrdinal == 0) {
            switchButton.setChecked(true);
            holder.c(true);
        } else if (iOrdinal == 1) {
            switchButton.setChecked(false);
            holder.c(false);
        } else if (iOrdinal == 2) {
            Intrinsics.checkNotNullExpressionValue(switchButton, "");
            switchButton.setVisibility(8);
        } else if (iOrdinal == 3) {
            switchButton.setChecked(true);
            holder.c(true);
            switchButton.setEnabled(false);
            switchButton.setAlpha(0.5f);
        }
        switchButton.setOnCheckedChangeListener(new p(2, holder, jVar));
        switchButton.setContentDescription(lVar.q);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        LayoutInflater layoutInflater = this.h;
        if (layoutInflater == null) {
            Intrinsics.m("inflater");
            throw null;
        }
        com.onetrust.otpublishers.headless.databinding.d dVarA = com.onetrust.otpublishers.headless.databinding.d.a(layoutInflater, parent);
        Intrinsics.checkNotNullExpressionValue(dVarA, "inflate(inflater, parent, false)");
        return new J(dVarA, this.c, this.d, this.e, this.f, this.g);
    }
}
