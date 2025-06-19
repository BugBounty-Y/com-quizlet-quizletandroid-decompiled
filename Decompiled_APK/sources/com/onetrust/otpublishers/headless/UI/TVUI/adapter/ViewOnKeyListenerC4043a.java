package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.graphics.Color;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3617f4;
import com.google.android.gms.measurement.internal.Z;
import org.json.JSONArray;
import org.json.JSONException;

/* renamed from: com.onetrust.otpublishers.headless.UI.TVUI.adapter.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class ViewOnKeyListenerC4043a implements View.OnKeyListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractC1361d0 b;
    public final /* synthetic */ F0 c;

    public /* synthetic */ ViewOnKeyListenerC4043a(AbstractC1361d0 abstractC1361d0, F0 f0, int i) {
        this.a = i;
        this.b = abstractC1361d0;
        this.c = f0;
    }

    /* JADX WARN: Type inference failed for: r2v2, types: [androidx.fragment.app.Fragment, com.onetrust.otpublishers.headless.UI.TVUI.adapter.j] */
    @Override // android.view.View.OnKeyListener
    public final boolean onKey(View view, int i, KeyEvent keyEvent) {
        Button button;
        Button button2;
        View view2;
        Button button3;
        switch (this.a) {
            case 0:
                c cVar = (c) this.b;
                int iA = AbstractC3617f4.a(i, keyEvent);
                C4044b c4044b = (C4044b) this.c;
                com.onetrust.otpublishers.headless.UI.TVUI.fragments.s sVar = cVar.a;
                if (iA != 22) {
                    if (c4044b.getAdapterPosition() == 0 && AbstractC3617f4.a(i, keyEvent) == 25) {
                        if (sVar.G.equals("A_F")) {
                            button = sVar.y;
                        } else if (sVar.G.equals("G_L")) {
                            button = sVar.z;
                        } else if (sVar.G.equals("M_R")) {
                            button = sVar.A;
                        } else if (sVar.G.equals("S_Z")) {
                            button = sVar.B;
                        }
                        button.requestFocus();
                        break;
                    }
                } else {
                    cVar.e = c4044b.getAdapterPosition();
                    sVar.N();
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar2 = cVar.d;
                    c4044b.a.setTextColor(Color.parseColor((String) cVar2.j.B.g));
                    c4044b.c.setBackgroundColor(Color.parseColor((String) cVar2.j.B.f));
                    break;
                }
                break;
            case 1:
                k kVar = (k) this.c;
                l lVar = (l) this.b;
                int iA2 = AbstractC3617f4.a(i, keyEvent);
                ?? r2 = (Fragment) lVar.e;
                if (iA2 == 22 || AbstractC3617f4.a(i, keyEvent) == 21) {
                    try {
                        r2.a(((JSONArray) lVar.f).getJSONObject(kVar.getAdapterPosition()));
                    } catch (JSONException e) {
                        Z.p("Error in navigating to subgroups : ", e, "OneTrust", 6);
                    }
                }
                if (AbstractC3617f4.a(i, keyEvent) == 24) {
                    r2.a();
                    break;
                }
                break;
            case 2:
                r rVar = (r) this.b;
                int iA3 = AbstractC3617f4.a(i, keyEvent);
                q qVar = (q) this.c;
                com.onetrust.otpublishers.headless.UI.TVUI.fragments.n nVar = rVar.a;
                if (iA3 != 22) {
                    if (qVar.getAdapterPosition() == 0 && AbstractC3617f4.a(i, keyEvent) == 25) {
                        if (nVar.y.equals("A_F")) {
                            button2 = nVar.s;
                        } else if (nVar.y.equals("G_L")) {
                            button2 = nVar.t;
                        } else if (nVar.y.equals("M_R")) {
                            button2 = nVar.u;
                        } else if (nVar.y.equals("S_Z")) {
                            button2 = nVar.v;
                        }
                        button2.requestFocus();
                        break;
                    }
                } else {
                    rVar.e = qVar.getAdapterPosition();
                    nVar.B = true;
                    com.onetrust.otpublishers.headless.UI.TVUI.fragments.l lVar2 = nVar.o;
                    if (lVar2.g.getVisibility() != 0) {
                        lVar2.d.setFocusableInTouchMode(true);
                        if (!com.onetrust.otpublishers.headless.Internal.a.j(lVar2.d.getText().toString())) {
                            view2 = lVar2.d;
                        }
                        nVar.r.clearFocus();
                        nVar.q.clearFocus();
                        nVar.p.clearFocus();
                        com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar3 = rVar.c;
                        qVar.a.setTextColor(Color.parseColor((String) cVar3.j.B.g));
                        qVar.b.setBackgroundColor(Color.parseColor((String) cVar3.j.B.f));
                        break;
                    } else {
                        view2 = lVar2.g;
                    }
                    view2.requestFocus();
                    nVar.r.clearFocus();
                    nVar.q.clearFocus();
                    nVar.p.clearFocus();
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar32 = rVar.c;
                    qVar.a.setTextColor(Color.parseColor((String) cVar32.j.B.g));
                    qVar.b.setBackgroundColor(Color.parseColor((String) cVar32.j.B.f));
                }
                break;
            case 3:
                e eVar = (e) this.b;
                if (AbstractC3617f4.a(i, keyEvent) == 24) {
                    ((com.onetrust.otpublishers.headless.UI.TVUI.fragments.p) eVar.d).s.p(24);
                    ((z) this.c).itemView.setFocusable(false);
                    break;
                }
                break;
            case 4:
                e eVar2 = (e) this.b;
                if (AbstractC3617f4.a(i, keyEvent) == 24) {
                    ((com.onetrust.otpublishers.headless.UI.TVUI.fragments.p) eVar2.d).s.p(24);
                    ((w) this.c).itemView.setFocusable(false);
                    break;
                }
                break;
            case 5:
                e eVar3 = (e) this.b;
                if (AbstractC3617f4.a(i, keyEvent) == 24) {
                    ((com.onetrust.otpublishers.headless.UI.TVUI.fragments.p) eVar3.d).s.p(24);
                    ((y) this.c).itemView.setFocusable(false);
                    break;
                }
                break;
            case 6:
                e eVar4 = (e) this.b;
                if (AbstractC3617f4.a(i, keyEvent) == 24) {
                    ((com.onetrust.otpublishers.headless.UI.TVUI.fragments.p) eVar4.d).s.p(24);
                    ((x) this.c).itemView.setFocusable(false);
                    break;
                }
                break;
            default:
                B b = (B) this.b;
                int iA4 = AbstractC3617f4.a(i, keyEvent);
                A a = (A) this.c;
                com.onetrust.otpublishers.headless.UI.TVUI.fragments.s sVar2 = b.a;
                if (iA4 != 22) {
                    if (a.getAdapterPosition() == 0 && AbstractC3617f4.a(i, keyEvent) == 25) {
                        if (sVar2.G.equals("A_F")) {
                            button3 = sVar2.y;
                        } else if (sVar2.G.equals("G_L")) {
                            button3 = sVar2.z;
                        } else if (sVar2.G.equals("M_R")) {
                            button3 = sVar2.A;
                        } else if (sVar2.G.equals("S_Z")) {
                            button3 = sVar2.B;
                        }
                        button3.requestFocus();
                        break;
                    }
                } else {
                    b.g = a.getAdapterPosition();
                    sVar2.N();
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.c cVar4 = b.d;
                    a.a.setTextColor(Color.parseColor((String) cVar4.j.B.g));
                    a.c.setBackgroundColor(Color.parseColor((String) cVar4.j.B.f));
                    break;
                }
                break;
        }
        return true;
    }
}
