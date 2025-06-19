package com.onetrust.otpublishers.headless.UI.adapter;

import android.graphics.Color;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.RadioButton;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class B extends AbstractC1361d0 implements com.onetrust.otpublishers.headless.UI.a {
    public final String a;
    public final String b;
    public final int c = -1;
    public RadioButton d;
    public final ArrayList e;
    public final com.onetrust.otpublishers.headless.Internal.Helper.k f;
    public final boolean g;
    public final String h;
    public final com.onetrust.otpublishers.headless.UI.UIProperty.e i;

    public B(ArrayList arrayList, String str, String str2, com.onetrust.otpublishers.headless.Internal.Helper.k kVar, boolean z, String str3, com.onetrust.otpublishers.headless.UI.UIProperty.e eVar) {
        this.e = arrayList;
        this.b = str;
        this.a = str2;
        this.f = kVar;
        this.g = z;
        this.i = eVar;
        this.h = str3;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.e.size();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        final A a = (A) f0;
        final int adapterPosition = a.getAdapterPosition();
        CheckBox checkBox = a.a;
        boolean z = this.g;
        checkBox.setEnabled(z);
        androidx.navigation.internal.m mVar = this.i.l;
        String str = this.h;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            checkBox.setTextColor(Color.parseColor(str));
        }
        String str2 = (String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
            checkBox.setTextSize(Float.parseFloat(str2));
        }
        boolean zJ = com.onetrust.otpublishers.headless.Internal.a.j(str);
        RadioButton radioButton = a.b;
        if (!zJ) {
            radioButton.setTextColor(Color.parseColor(str));
        }
        String str3 = (String) ((com.google.android.gms.cloudmessaging.k) mVar.d).d;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
            radioButton.setTextSize(Float.parseFloat(str3));
        }
        if (z) {
            com.google.mlkit.common.internal.model.a.j(checkBox, Color.parseColor(str), Color.parseColor(str));
        }
        com.google.mlkit.common.internal.model.a.j(radioButton, Color.parseColor(str), Color.parseColor(str));
        String str4 = this.b;
        boolean zEquals = str4.equals("customPrefOptionType");
        ArrayList arrayList = this.e;
        com.onetrust.otpublishers.headless.Internal.Helper.k kVar = this.f;
        String str5 = this.a;
        if (!zEquals) {
            if (str4.equals("topicOptionType") && str5.equals("null")) {
                radioButton.setVisibility(8);
                checkBox.setVisibility(0);
                checkBox.setText(((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList.get(adapterPosition)).c);
                checkBox.setChecked(kVar.a(((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList.get(adapterPosition)).a, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList.get(adapterPosition)).j) == 1);
                final int i2 = 0;
                checkBox.setOnClickListener(new View.OnClickListener(this) { // from class: com.onetrust.otpublishers.headless.UI.adapter.z
                    public final /* synthetic */ B b;

                    {
                        this.b = this;
                    }

                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        com.onetrust.otpublishers.headless.UI.DataModels.d dVar;
                        String str6;
                        com.onetrust.otpublishers.headless.UI.DataModels.d dVar2;
                        String str7;
                        switch (i2) {
                            case 0:
                                B b = this.b;
                                boolean zIsChecked = a.a.isChecked();
                                ArrayList arrayList2 = b.e;
                                int i3 = adapterPosition;
                                com.onetrust.otpublishers.headless.Internal.Helper.k kVar2 = b.f;
                                if (zIsChecked) {
                                    String str8 = ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i3)).l;
                                    String str9 = ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i3)).a;
                                    Objects.requireNonNull(str9);
                                    kVar2.t(str8, str9, true);
                                    dVar = (com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i3);
                                    str6 = "OPT_IN";
                                } else {
                                    String str10 = ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i3)).l;
                                    String str11 = ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i3)).a;
                                    Objects.requireNonNull(str11);
                                    kVar2.t(str10, str11, false);
                                    dVar = (com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i3);
                                    str6 = "OPT_OUT";
                                }
                                dVar.h = str6;
                                break;
                            default:
                                B b2 = this.b;
                                boolean zIsChecked2 = a.a.isChecked();
                                ArrayList arrayList3 = b2.e;
                                int i4 = adapterPosition;
                                com.onetrust.otpublishers.headless.Internal.Helper.k kVar3 = b2.f;
                                if (zIsChecked2) {
                                    kVar3.g(((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).k, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).i, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).a, true);
                                    dVar2 = (com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4);
                                    str7 = "OPT_IN";
                                } else {
                                    kVar3.g(((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).k, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).i, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).a, false);
                                    dVar2 = (com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4);
                                    str7 = "OPT_OUT";
                                }
                                dVar2.h = str7;
                                break;
                        }
                    }
                });
                return;
            }
            return;
        }
        if ("MULTI_CHOICE".equals(str5)) {
            radioButton.setVisibility(8);
            checkBox.setVisibility(0);
            checkBox.setText(((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList.get(adapterPosition)).e);
            checkBox.setChecked(kVar.b(((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList.get(adapterPosition)).a, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList.get(adapterPosition)).j, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList.get(adapterPosition)).k) == 1);
            final int i3 = 1;
            checkBox.setOnClickListener(new View.OnClickListener(this) { // from class: com.onetrust.otpublishers.headless.UI.adapter.z
                public final /* synthetic */ B b;

                {
                    this.b = this;
                }

                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    com.onetrust.otpublishers.headless.UI.DataModels.d dVar;
                    String str6;
                    com.onetrust.otpublishers.headless.UI.DataModels.d dVar2;
                    String str7;
                    switch (i3) {
                        case 0:
                            B b = this.b;
                            boolean zIsChecked = a.a.isChecked();
                            ArrayList arrayList2 = b.e;
                            int i32 = adapterPosition;
                            com.onetrust.otpublishers.headless.Internal.Helper.k kVar2 = b.f;
                            if (zIsChecked) {
                                String str8 = ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i32)).l;
                                String str9 = ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i32)).a;
                                Objects.requireNonNull(str9);
                                kVar2.t(str8, str9, true);
                                dVar = (com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i32);
                                str6 = "OPT_IN";
                            } else {
                                String str10 = ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i32)).l;
                                String str11 = ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i32)).a;
                                Objects.requireNonNull(str11);
                                kVar2.t(str10, str11, false);
                                dVar = (com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList2.get(i32);
                                str6 = "OPT_OUT";
                            }
                            dVar.h = str6;
                            break;
                        default:
                            B b2 = this.b;
                            boolean zIsChecked2 = a.a.isChecked();
                            ArrayList arrayList3 = b2.e;
                            int i4 = adapterPosition;
                            com.onetrust.otpublishers.headless.Internal.Helper.k kVar3 = b2.f;
                            if (zIsChecked2) {
                                kVar3.g(((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).k, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).i, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).a, true);
                                dVar2 = (com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4);
                                str7 = "OPT_IN";
                            } else {
                                kVar3.g(((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).k, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).i, ((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4)).a, false);
                                dVar2 = (com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList3.get(i4);
                                str7 = "OPT_OUT";
                            }
                            dVar2.h = str7;
                            break;
                    }
                }
            });
        } else if ("SINGLE_CHOICE".equals(str5)) {
            radioButton.setText(((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList.get(adapterPosition)).e);
            radioButton.setTag(Integer.valueOf(adapterPosition));
            radioButton.setChecked(adapterPosition == this.c);
            checkBox.setVisibility(8);
            radioButton.setVisibility(0);
            if (this.d == null) {
                radioButton.setChecked(((com.onetrust.otpublishers.headless.UI.DataModels.d) arrayList.get(adapterPosition)).h.equals("OPT_IN"));
                this.d = radioButton;
            }
        }
        radioButton.setOnClickListener(new com.braze.ui.inappmessage.views.a(9, this, a));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        return new A(Z.c(viewGroup, R.layout.ot_uc_purposes_options_item, viewGroup, false));
    }

    @Override // com.onetrust.otpublishers.headless.UI.a
    public final void p(int i) {
        if (i == 4) {
            notifyDataSetChanged();
        }
    }
}
