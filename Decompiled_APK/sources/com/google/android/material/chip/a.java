package com.google.android.material.chip;

import android.widget.CompoundButton;
import androidx.appcompat.app.L;
import androidx.camera.camera2.internal.m0;
import androidx.compose.foundation.lazy.grid.m;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import com.onetrust.otpublishers.headless.UI.TVUI.adapter.l;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements CompoundButton.OnCheckedChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.widget.CompoundButton.OnCheckedChangeListener
    public final void onCheckedChanged(CompoundButton compoundButton, boolean z) throws JSONException {
        switch (this.a) {
            case 0:
                Chip chip = (Chip) this.b;
                com.google.android.material.internal.h hVar = chip.j;
                if (hVar != null) {
                    m0 m0Var = (m0) ((L) hVar).b;
                    if (!z ? m0Var.e(chip, m0Var.b) : m0Var.a(chip)) {
                        m0Var.d();
                    }
                }
                CompoundButton.OnCheckedChangeListener onCheckedChangeListener = chip.i;
                if (onCheckedChangeListener != null) {
                    onCheckedChangeListener.onCheckedChanged(compoundButton, z);
                    break;
                }
                break;
            case 1:
                com.onetrust.otpublishers.headless.UI.TVUI.fragments.b bVar = (com.onetrust.otpublishers.headless.UI.TVUI.fragments.b) this.b;
                String strTrim = bVar.j.optString("id").trim();
                bVar.i.updateVendorConsent(OTVendorListMode.GOOGLE, strTrim, z);
                if (bVar.o) {
                    m mVar = new m(15, 4);
                    mVar.c = strTrim;
                    mVar.b = z ? 1 : 0;
                    com.onetrust.otpublishers.headless.Internal.Event.a aVar = bVar.n;
                    if (aVar != null) {
                        aVar.a(mVar);
                    } else {
                        OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                    }
                }
                bVar.k.getClass();
                break;
            case 2:
                com.onetrust.otpublishers.headless.UI.TVUI.fragments.d dVar = (com.onetrust.otpublishers.headless.UI.TVUI.fragments.d) this.b;
                String strOptString = dVar.u.optString("CustomGroupId");
                dVar.k.updatePurposeLegitInterest(strOptString, z);
                m mVar2 = new m(11, 4);
                mVar2.c = strOptString;
                mVar2.b = z ? 1 : 0;
                com.onetrust.otpublishers.headless.Internal.Event.a aVar2 = dVar.w;
                if (aVar2 != null) {
                    aVar2.a(mVar2);
                } else {
                    OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                }
                if (dVar.u.has("SubGroups") && com.onetrust.otpublishers.headless.Internal.a.j(dVar.u.optString("Parent")) && dVar.f1) {
                    OTPublishersHeadlessSDK oTPublishersHeadlessSDK = dVar.k;
                    JSONObject jSONObject = dVar.u;
                    for (int i = 0; i < jSONObject.getJSONArray("SubGroups").length(); i++) {
                        try {
                            oTPublishersHeadlessSDK.updatePurposeLegitInterest(jSONObject.getJSONArray("SubGroups").getJSONObject(i).optString("CustomGroupId"), z);
                        } catch (Exception e) {
                            Z.n("error while updating subgroup LI status on TV, err : ", e, "OneTrust", 6);
                        }
                    }
                }
                l lVar = dVar.y;
                if (lVar != null) {
                    lVar.notifyDataSetChanged();
                }
                dVar.f1 = true;
                break;
            default:
                com.quizlet.quizletandroid.ui.setcreation.activities.h hVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.h) this.b;
                hVar2.getClass();
                hVar2.t = compoundButton.isChecked();
                break;
        }
    }
}
