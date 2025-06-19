package com.onetrust.otpublishers.headless.UI.adapter;

import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.ScanDocumentFragment;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* renamed from: com.onetrust.otpublishers.headless.UI.adapter.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class ViewOnClickListenerC4055k implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ ViewOnClickListenerC4055k(Object obj, int i, Object obj2, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
        this.d = obj2;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        Object obj = this.d;
        int i = this.b;
        Object obj2 = this.c;
        switch (this.a) {
            case 0:
                m mVar = (m) obj2;
                if (!mVar.g.isAdded()) {
                    Bundle bundle = new Bundle();
                    JSONObject jSONObject = (JSONObject) obj;
                    bundle.putString("SUBGROUP_ARRAY", jSONObject.toString());
                    if (jSONObject.has("SubGroups")) {
                        bundle.putInt("PARENT_POSITION", i);
                    }
                    bundle.putString("sdkLevelOptOutShow", mVar.l.H);
                    mVar.g.setArguments(bundle);
                    com.google.mlkit.common.internal.model.a.o(mVar.g, (androidx.fragment.app.I) mVar.e, OTFragmentTags.OT_PREFERENCE_CENTER_DETAILS_FRAGMENT_TAG);
                    break;
                }
                break;
            case 1:
                ScanDocumentFragment scanDocumentFragment = ((com.quizlet.quizletandroid.ui.setcreation.a) obj2).q;
                if (scanDocumentFragment != null) {
                    if (i == R.id.publishSet) {
                        scanDocumentFragment.Y().a.z("ocr_tap_publish_set");
                        com.quizlet.quizletandroid.ui.setcreation.viewmodels.h hVarE0 = scanDocumentFragment.e0();
                        String term = scanDocumentFragment.X();
                        String definition = scanDocumentFragment.W();
                        hVarE0.getClass();
                        Intrinsics.checkNotNullParameter(term, "term");
                        Intrinsics.checkNotNullParameter(definition, "definition");
                        hVarE0.H(term, definition);
                        hVarE0.F(hVarE0.D().getTitle());
                    } else if (i == R.id.previewSet) {
                        scanDocumentFragment.Y().a.z("ocr_tap_preview_set");
                        scanDocumentFragment.T();
                        scanDocumentFragment.requireActivity().finish();
                    } else if (i == R.id.deleteSet) {
                        scanDocumentFragment.Y().a.z("ocr_tap_delete_set");
                        e.a aVar = new e.a(scanDocumentFragment.requireContext());
                        aVar.c(R.string.delete_set_confirmation);
                        aVar.e(R.string.yes, new com.quizlet.quizletandroid.ui.setcreation.fragments.m(scanDocumentFragment, 5));
                        aVar.d(R.string.no, new com.quizlet.infra.legacysyncengine.models.serializers.a(29));
                        aVar.g();
                    } else {
                        timber.log.c.a.e(new IllegalArgumentException(AbstractC0147y.c(i, "Option selected ", " is not supported. Supported options are: publishSet (2131429075), previewSet (2131429053) and deleteSet (2131427999)")));
                    }
                }
                ((com.google.android.material.bottomsheet.h) obj).dismiss();
                break;
            case 2:
                EditSetFragment editSetFragment = (EditSetFragment) obj2;
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = editSetFragment.A;
                if (fVar != null) {
                    fVar.f(i, (DBTerm) obj);
                }
                editSetFragment.h0();
                break;
            default:
                com.quizlet.uicommon.ui.common.dialogs.e eVar = (com.quizlet.uicommon.ui.common.dialogs.e) obj2;
                boolean z = true;
                if (i == 1) {
                    HashMap map = eVar.q.g;
                    if (map != null) {
                        for (Integer num : map.keySet()) {
                            if (eVar.r.containsKey(num)) {
                                com.quizlet.features.setpage.utils.setpermissions.b bVar = (com.quizlet.features.setpage.utils.setpermissions.b) map.get(num);
                                EditText editTextF = eVar.f(num.intValue());
                                bVar.getClass();
                                String string = editTextF.getText().toString().length() == 0 ? bVar.a.getString(R.string.non_blank_password) : null;
                                if (string != null) {
                                    ((QFormField) eVar.r.get(num)).setError(string);
                                    z = false;
                                }
                            } else {
                                timber.log.c.a(new RuntimeException("Attempting to call validator on missing EditText"));
                            }
                        }
                    }
                    if (!z) {
                    }
                } else {
                    int i2 = com.quizlet.uicommon.ui.common.dialogs.e.s;
                }
                com.quizlet.uicommon.ui.common.dialogs.f fVar2 = (com.quizlet.uicommon.ui.common.dialogs.f) obj;
                if (fVar2 != null) {
                    eVar.getClass();
                    fVar2.c(eVar, i);
                    break;
                } else {
                    eVar.dismiss();
                    break;
                }
                break;
        }
    }
}
