package com.onetrust.otpublishers.headless.UI.adapter;

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
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class E extends V {
    public final /* synthetic */ int c = 0;
    public final com.onetrust.otpublishers.headless.UI.DataModels.l d;
    public final OTConfiguration e;
    public LayoutInflater f;
    public final kotlin.jvm.internal.r g;
    public final kotlin.jvm.internal.r h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(com.onetrust.otpublishers.headless.UI.DataModels.l vendorListData, OTConfiguration oTConfiguration, com.onetrust.otpublishers.headless.UI.fragment.E onItemToggleCheckedChange, com.onetrust.otpublishers.headless.UI.fragment.F onItemClicked) {
        super(new s(1));
        Intrinsics.checkNotNullParameter(vendorListData, "vendorListData");
        Intrinsics.checkNotNullParameter(onItemToggleCheckedChange, "onItemToggleCheckedChange");
        Intrinsics.checkNotNullParameter(onItemClicked, "onItemClicked");
        this.d = vendorListData;
        this.e = oTConfiguration;
        this.g = onItemToggleCheckedChange;
        this.h = onItemClicked;
    }

    @Override // androidx.recyclerview.widget.V, androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        switch (this.c) {
            case 0:
                return ((C1364f) this.b).f.size() + 1;
            default:
                return super.getItemCount() + 1;
        }
    }

    @Override // androidx.recyclerview.widget.V, androidx.recyclerview.widget.AbstractC1361d0
    public final void onAttachedToRecyclerView(RecyclerView recyclerView) {
        switch (this.c) {
            case 0:
                Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
                super.onAttachedToRecyclerView(recyclerView);
                LayoutInflater layoutInflaterFrom = LayoutInflater.from(recyclerView.getContext());
                Intrinsics.checkNotNullExpressionValue(layoutInflaterFrom, "from(recyclerView.context)");
                this.f = layoutInflaterFrom;
                break;
            default:
                Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
                super.onAttachedToRecyclerView(recyclerView);
                LayoutInflater layoutInflaterFrom2 = LayoutInflater.from(recyclerView.getContext());
                Intrinsics.checkNotNullExpressionValue(layoutInflaterFrom2, "from(recyclerView.context)");
                this.f = layoutInflaterFrom2;
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:98:0x0275  */
    @Override // androidx.recyclerview.widget.AbstractC1361d0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onBindViewHolder(androidx.recyclerview.widget.F0 r23, int r24) throws android.content.res.Resources.NotFoundException, java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 736
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.UI.adapter.E.onBindViewHolder(androidx.recyclerview.widget.F0, int):void");
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        switch (this.c) {
            case 0:
                Intrinsics.checkNotNullParameter(parent, "parent");
                LayoutInflater layoutInflater = this.f;
                if (layoutInflater == null) {
                    Intrinsics.m("inflater");
                    throw null;
                }
                View viewInflate = layoutInflater.inflate(R.layout.ot_vendors_list_item, parent, false);
                int i2 = R.id.legit_int_switchButton;
                SwitchCompat switchCompat = (SwitchCompat) AbstractC3375o2.c(R.id.legit_int_switchButton, viewInflate);
                if (switchCompat != null) {
                    i2 = R.id.show_more;
                    ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.show_more, viewInflate);
                    if (imageView != null) {
                        i2 = R.id.switchButton;
                        SwitchCompat switchCompat2 = (SwitchCompat) AbstractC3375o2.c(R.id.switchButton, viewInflate);
                        if (switchCompat2 != null) {
                            i2 = R.id.vendor_name;
                            TextView textView = (TextView) AbstractC3375o2.c(R.id.vendor_name, viewInflate);
                            if (textView != null) {
                                i2 = R.id.vendors_privacy_notice;
                                if (((TextView) AbstractC3375o2.c(R.id.vendors_privacy_notice, viewInflate)) != null) {
                                    i2 = R.id.view3;
                                    View viewC = AbstractC3375o2.c(R.id.view3, viewInflate);
                                    if (viewC != null) {
                                        i2 = R.id.view_powered_by_logo;
                                        TextView textView2 = (TextView) AbstractC3375o2.c(R.id.view_powered_by_logo, viewInflate);
                                        if (textView2 != null) {
                                            i2 = R.id.vl_items;
                                            RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.vl_items, viewInflate);
                                            if (relativeLayout != null) {
                                                com.onetrust.otpublishers.headless.databinding.e eVar = new com.onetrust.otpublishers.headless.databinding.e((RelativeLayout) viewInflate, switchCompat, imageView, switchCompat2, textView, viewC, textView2, relativeLayout);
                                                Intrinsics.checkNotNullExpressionValue(eVar, "inflate(inflater, parent, false)");
                                                return new D(eVar, this.d, this.e, (com.onetrust.otpublishers.headless.UI.fragment.E) this.g, (com.onetrust.otpublishers.headless.UI.fragment.F) this.h);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i2)));
            default:
                Intrinsics.checkNotNullParameter(parent, "parent");
                LayoutInflater layoutInflater2 = this.f;
                if (layoutInflater2 == null) {
                    Intrinsics.m("inflater");
                    throw null;
                }
                com.onetrust.otpublishers.headless.databinding.d dVarA = com.onetrust.otpublishers.headless.databinding.d.a(layoutInflater2, parent);
                Intrinsics.checkNotNullExpressionValue(dVarA, "inflate(inflater, parent, false)");
                return new L(dVarA, this.d, this.e, (com.onetrust.otpublishers.headless.UI.fragment.E) this.g, (com.onetrust.otpublishers.headless.UI.fragment.F) this.h);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(com.onetrust.otpublishers.headless.UI.DataModels.l vendorListData, OTConfiguration oTConfiguration, com.onetrust.otpublishers.headless.UI.fragment.E onItemToggleCheckedChange, com.onetrust.otpublishers.headless.UI.fragment.F onItemClicked, byte b) {
        super(new s(1));
        Intrinsics.checkNotNullParameter(vendorListData, "vendorListData");
        Intrinsics.checkNotNullParameter(onItemToggleCheckedChange, "onItemToggleCheckedChange");
        Intrinsics.checkNotNullParameter(onItemClicked, "onItemClicked");
        this.d = vendorListData;
        this.e = oTConfiguration;
        this.g = onItemToggleCheckedChange;
        this.h = onItemClicked;
    }
}
