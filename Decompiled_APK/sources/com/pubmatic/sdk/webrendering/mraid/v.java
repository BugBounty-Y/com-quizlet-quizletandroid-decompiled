package com.pubmatic.sdk.webrendering.mraid;

import android.view.View;
import com.pubmatic.sdk.webrendering.mraid.POBMraidController;
import org.json.JSONException;

/* loaded from: classes2.dex */
public class v implements View.OnLayoutChangeListener {
    final /* synthetic */ POBMraidController.i a;

    public v(POBMraidController.i iVar) {
        this.a = iVar;
    }

    @Override // android.view.View.OnLayoutChangeListener
    public void onLayoutChange(View view, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) throws JSONException {
        POBMraidController.i iVar = this.a;
        POBMraidController pOBMraidController = POBMraidController.this;
        pOBMraidController.initProperties(iVar.e, pOBMraidController.mraidInitState);
    }
}
