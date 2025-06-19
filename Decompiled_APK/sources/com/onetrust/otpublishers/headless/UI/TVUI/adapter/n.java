package com.onetrust.otpublishers.headless.UI.TVUI.adapter;

import android.content.Context;
import android.widget.CompoundButton;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.recyclerview.widget.AbstractC1361d0;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.UI.adapter.C4056l;
import java.util.ArrayList;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class n implements CompoundButton.OnCheckedChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractC1361d0 b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ n(AbstractC1361d0 abstractC1361d0, Object obj, Object obj2, int i) {
        this.a = i;
        this.b = abstractC1361d0;
        this.c = obj;
        this.d = obj2;
    }

    @Override // android.widget.CompoundButton.OnCheckedChangeListener
    public final void onCheckedChanged(CompoundButton compoundButton, boolean z) throws JSONException {
        String str;
        switch (this.a) {
            case 0:
                p pVar = (p) this.b;
                boolean zIsChecked = ((o) this.c).b.isChecked();
                String str2 = (String) this.d;
                com.onetrust.otpublishers.headless.UI.TVUI.fragments.m mVar = (com.onetrust.otpublishers.headless.UI.TVUI.fragments.m) pVar.d;
                if (!zIsChecked) {
                    ((ArrayList) pVar.e).remove(str2);
                    mVar.g = (ArrayList) pVar.e;
                    str = "Purposes Removed : ";
                } else if (!((ArrayList) pVar.e).contains(str2)) {
                    ((ArrayList) pVar.e).add(str2);
                    mVar.g = (ArrayList) pVar.e;
                    str = "Purposes Added : ";
                }
                OTLogger.c("OneTrust", 4, AbstractC0147y.d(str, str2));
                break;
            default:
                JSONObject jSONObject = (JSONObject) this.c;
                com.onetrust.otpublishers.headless.UI.adapter.m mVar2 = (com.onetrust.otpublishers.headless.UI.adapter.m) this.b;
                OTPublishersHeadlessSDK oTPublishersHeadlessSDK = mVar2.c;
                try {
                    String string = jSONObject.getString("CustomGroupId");
                    oTPublishersHeadlessSDK.updatePurposeConsent(string, z);
                    OTLogger.c("OTPCGroupsAdapter", 3, "updated consent of group : " + string + ":" + oTPublishersHeadlessSDK.getPurposeConsentLocal(string));
                    androidx.compose.foundation.lazy.grid.m mVar3 = new androidx.compose.foundation.lazy.grid.m(7, 4);
                    mVar3.c = string;
                    mVar3.b = z ? 1 : 0;
                    com.onetrust.otpublishers.headless.Internal.Event.a aVar = mVar2.f;
                    if (aVar != null) {
                        aVar.a(mVar3);
                    } else {
                        OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
                    }
                    C4056l c4056l = (C4056l) this.d;
                    Context context = mVar2.e;
                    if (!z) {
                        assistantMode.utils.studiableMetadata.b.s(context, c4056l.d, mVar2.i, mVar2.k);
                        break;
                    } else {
                        assistantMode.utils.studiableMetadata.b.s(context, c4056l.d, mVar2.i, mVar2.j);
                        break;
                    }
                } catch (JSONException e) {
                    Z.p("error while updating parent ", e, "OneTrust", 6);
                }
        }
    }
}
