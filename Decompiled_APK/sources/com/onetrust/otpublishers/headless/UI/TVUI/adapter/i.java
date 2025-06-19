package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.camera.camera2.internal.c0;
import androidx.fragment.app.I;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.quizletandroid.R;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class i extends AbstractC1361d0 {
    public final com.onetrust.otpublishers.headless.UI.TVUI.fragments.k a;
    public final JSONArray b;
    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.c c = com.onetrust.otpublishers.headless.UI.TVUI.datautils.c.i();
    public int d;
    public final JSONObject e;

    public i(I i, JSONArray jSONArray, com.onetrust.otpublishers.headless.UI.TVUI.fragments.k kVar) {
        this.b = jSONArray;
        this.a = kVar;
        this.e = new com.onetrust.otpublishers.headless.Internal.Preferences.e(i).h();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        return this.b.length();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, final int i) throws JSONException {
        JSONException jSONException;
        StringBuilder sb;
        StringIndexOutOfBoundsException stringIndexOutOfBoundsException;
        final h hVar = (h) f0;
        String str = "GroupNameOTT";
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar = this.c;
        try {
            final c0 c0Var = cVar.j.B;
            int adapterPosition = hVar.getAdapterPosition();
            TextView textView = hVar.a;
            TextView textView2 = hVar.b;
            LinearLayout linearLayout = hVar.c;
            JSONObject jSONObject = this.b.getJSONObject(adapterPosition);
            textView.setTextColor(Color.parseColor((String) cVar.j.B.c));
            linearLayout.setBackgroundColor(Color.parseColor((String) c0Var.b));
            Context context = linearLayout.getContext();
            if (com.onetrust.otpublishers.headless.Internal.a.j(jSONObject.optString("GroupNameOTT"))) {
                str = "GroupName";
            }
            assistantMode.utils.studiableMetadata.b.r(context, textView, jSONObject.optString(str));
            textView2.setTextColor(Color.parseColor((String) cVar.j.B.c));
            String strM = assistantMode.utils.studiableMetadata.b.m(linearLayout.getContext(), this.e, jSONObject, cVar.f, cVar.e);
            if (com.onetrust.otpublishers.headless.Internal.a.j(strM)) {
                textView2.setVisibility(8);
            } else {
                try {
                    assistantMode.utils.studiableMetadata.b.r(linearLayout.getContext(), textView2, strM);
                    textView2.setVisibility(0);
                } catch (StringIndexOutOfBoundsException e) {
                    stringIndexOutOfBoundsException = e;
                    sb = new StringBuilder("TV PC: error in rendering groups due to corrupted data,  ");
                    sb.append(stringIndexOutOfBoundsException);
                    OTLogger.c("OneTrust", 6, sb.toString());
                } catch (JSONException e2) {
                    jSONException = e2;
                    sb = new StringBuilder("TV PC: error in rendering groups ");
                    sb.append(jSONException.getMessage());
                    OTLogger.c("OneTrust", 6, sb.toString());
                }
            }
            try {
                hVar.itemView.setOnFocusChangeListener(new f(this, jSONObject, hVar, c0Var, 0));
                hVar.itemView.setOnKeyListener(new View.OnKeyListener() { // from class: com.onetrust.otpublishers.headless.UI.TVUI.adapter.g
                    @Override // android.view.View.OnKeyListener
                    public final boolean onKey(View view, int i2, KeyEvent keyEvent) {
                        View view2;
                        i iVar = this.a;
                        int iA = AbstractC3617f4.a(i2, keyEvent);
                        h hVar2 = hVar;
                        com.onetrust.otpublishers.headless.UI.TVUI.fragments.k kVar = iVar.a;
                        if (iA != 22) {
                            if (AbstractC3617f4.a(i2, keyEvent) == 24) {
                                kVar.s.notifyDataSetChanged();
                            }
                            if (hVar2.getAdapterPosition() == 0 && AbstractC3617f4.a(i2, keyEvent) == 25) {
                                hVar2.c.requestFocus();
                                return true;
                            }
                            if (i != iVar.b.length() - 1 || AbstractC3617f4.a(i2, keyEvent) != 26) {
                                return false;
                            }
                            kVar.t = false;
                            kVar.e.requestFocus();
                            return true;
                        }
                        int adapterPosition2 = hVar2.getAdapterPosition();
                        iVar.d = adapterPosition2;
                        kVar.t = true;
                        com.onetrust.otpublishers.headless.UI.TVUI.fragments.d dVar = kVar.o;
                        if (dVar.u.optBoolean("IS_PARTNERS_LINK")) {
                            view2 = dVar.r;
                        } else if (dVar.B.getVisibility() == 0) {
                            view2 = dVar.B;
                        } else {
                            if (dVar.C.getVisibility() != 0) {
                                if (dVar.b.getVisibility() == 0) {
                                    view2 = dVar.b;
                                }
                                Bundle bundle = new Bundle();
                                bundle.putInt("OT_FOCUSED_PC_LIST_ITEM", adapterPosition2);
                                kVar.setArguments(bundle);
                                c0 c0Var2 = c0Var;
                                hVar2.c.setBackgroundColor(Color.parseColor((String) c0Var2.f));
                                hVar2.a.setTextColor(Color.parseColor((String) c0Var2.g));
                                hVar2.b.setTextColor(Color.parseColor((String) c0Var2.g));
                                return true;
                            }
                            view2 = dVar.C;
                        }
                        view2.requestFocus();
                        Bundle bundle2 = new Bundle();
                        bundle2.putInt("OT_FOCUSED_PC_LIST_ITEM", adapterPosition2);
                        kVar.setArguments(bundle2);
                        c0 c0Var22 = c0Var;
                        hVar2.c.setBackgroundColor(Color.parseColor((String) c0Var22.f));
                        hVar2.a.setTextColor(Color.parseColor((String) c0Var22.g));
                        hVar2.b.setTextColor(Color.parseColor((String) c0Var22.g));
                        return true;
                    }
                });
            } catch (StringIndexOutOfBoundsException e3) {
                e = e3;
                stringIndexOutOfBoundsException = e;
                sb = new StringBuilder("TV PC: error in rendering groups due to corrupted data,  ");
                sb.append(stringIndexOutOfBoundsException);
                OTLogger.c("OneTrust", 6, sb.toString());
            } catch (JSONException e4) {
                e = e4;
                jSONException = e;
                sb = new StringBuilder("TV PC: error in rendering groups ");
                sb.append(jSONException.getMessage());
                OTLogger.c("OneTrust", 6, sb.toString());
            }
        } catch (StringIndexOutOfBoundsException e5) {
            e = e5;
        } catch (JSONException e6) {
            e = e6;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        return new h(Z.c(viewGroup, R.layout.ot_pc_list_item_tv, viewGroup, false));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onViewAttachedToWindow(F0 f0) {
        h hVar = (h) f0;
        super.onViewAttachedToWindow(hVar);
        if (hVar.getAdapterPosition() == this.d) {
            hVar.itemView.requestFocus();
        }
    }
}
