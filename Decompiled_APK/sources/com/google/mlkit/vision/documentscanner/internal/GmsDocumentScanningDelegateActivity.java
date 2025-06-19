package com.google.mlkit.vision.documentscanner.internal;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.os.SystemClock;
import androidx.activity.s;
import com.android.billingclient.api.B;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3588c;
import com.google.android.gms.internal.mlkit_vision_document_scanner.EnumC3602d5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.EnumC3610e5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.H4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.I4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.J4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.p7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.r7;
import com.google.firebase.messaging.u;
import com.google.mlkit.common.sdkinternal.f;
import com.quizlet.data.interactor.folderwithcreator.m;
import java.util.ArrayList;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class GmsDocumentScanningDelegateActivity extends s {
    public final p7 a = r7.b();
    public final com.quizlet.data.repository.searchexplanations.c b = new com.quizlet.data.repository.searchexplanations.c(f.c().b(), 9);
    public J4 c;
    public long d;
    public long e;

    public static Intent o(Context context, Intent intent) {
        Intent action = new Intent().setPackage("com.google.android.gms").setAction("com.google.android.gms.mlkit.ACTION_SCAN_DOCUMENT");
        ApplicationInfo applicationInfo = context.getApplicationInfo();
        int i = applicationInfo.labelRes;
        return action.putExtra("string_extra_calling_app_name", i != 0 ? context.getString(i) : context.getPackageManager().getApplicationLabel(applicationInfo).toString()).putExtras(intent).setFlags(1);
    }

    @Override // androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        int i;
        super.onCreate(bundle);
        Intent intent = getIntent();
        G4 g4 = new G4();
        ArrayList parcelableArrayListExtra = intent.getParcelableArrayListExtra("uri_array_extra_initial_image_uris");
        if (parcelableArrayListExtra != null) {
            g4.a = Integer.valueOf(parcelableArrayListExtra.size() & SubsamplingScaleImageView.TILE_SIZE_AUTO);
        }
        int intExtra = intent.getIntExtra("int_extra_default_capture_mode", -1);
        g4.c = intExtra != 1 ? intExtra != 2 ? H4.MODE_UNKNOWN : H4.MODE_MANUAL : H4.MODE_AUTO;
        g4.d = Boolean.valueOf(intent.getBooleanExtra("boolean_extra_flash_mode_change_allowed", false));
        g4.e = Boolean.valueOf(intent.getBooleanExtra("boolean_extra_gallery_import_allowed", false));
        g4.f = Boolean.valueOf(intent.getIntExtra("int_extra_page_limit_max", -1) != 1);
        g4.b = Integer.valueOf(intent.getIntExtra("int_extra_page_limit_max", -1));
        g4.k = Boolean.valueOf(intent.getBooleanExtra("boolean_extra_enable_all_new_features_by_default", false));
        g4.g = Boolean.valueOf(intent.getBooleanExtra("boolean_extra_filter_allowed", false));
        g4.i = Boolean.valueOf(intent.getBooleanExtra("boolean_extra_shadow_removal_allowed", false));
        g4.j = Boolean.valueOf(intent.getBooleanExtra("boolean_extra_stain_removal_allowed", false));
        Object[] objArrCopyOf = new Object[4];
        int[] intArrayExtra = intent.getIntArrayExtra("int_array_extra_result_formats");
        if (intArrayExtra != null) {
            int i2 = 0;
            i = 0;
            while (i2 < intArrayExtra.length) {
                int i3 = intArrayExtra[i2];
                I4 i4 = i3 != 101 ? i3 != 102 ? I4.FORMAT_UNKNOWN : I4.FORMAT_PDF : I4.FORMAT_JPEG;
                int i5 = i + 1;
                int length = objArrCopyOf.length;
                if (length < i5) {
                    int i6 = length + (length >> 1) + 1;
                    if (i6 < i5) {
                        int iHighestOneBit = Integer.highestOneBit(i);
                        i6 = iHighestOneBit + iHighestOneBit;
                    }
                    if (i6 < 0) {
                        i6 = Integer.MAX_VALUE;
                    }
                    objArrCopyOf = Arrays.copyOf(objArrCopyOf, i6);
                }
                objArrCopyOf[i] = i4;
                i2++;
                i = i5;
            }
        } else {
            i = 0;
        }
        g4.l = AbstractC3588c.h(i, objArrCopyOf);
        g4.h = Boolean.valueOf(intent.getBooleanExtra("boolean_extra_page_edit_listener_enabled", false));
        this.c = new J4(g4);
        androidx.activity.result.b bVarRegisterForActivityResult = registerForActivityResult(new androidx.activity.result.contract.b(4), new B(this, 2));
        if (bundle != null) {
            this.d = bundle.getLong("elapsedStartTimeMsKey");
            this.e = bundle.getLong("epochStartTimeMsKey");
            return;
        }
        this.d = SystemClock.elapsedRealtime();
        this.e = System.currentTimeMillis();
        m mVar = new m();
        u uVar = new u();
        uVar.c = this.c;
        mVar.c = new L5(uVar);
        this.a.a(new com.quizlet.data.repository.widget.b(mVar), EnumC3610e5.ON_DEVICE_DOCUMENT_SCANNER_UI_START);
        bVarRegisterForActivityResult.a(o(this, getIntent()));
    }

    @Override // androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        bundle.putLong("elapsedStartTimeMsKey", this.d);
        bundle.putLong("epochStartTimeMsKey", this.e);
    }

    public final void q(EnumC3602d5 enumC3602d5, int i) {
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        long jCurrentTimeMillis = System.currentTimeMillis();
        m mVar = new m();
        u uVar = new u();
        uVar.a = Long.valueOf((jElapsedRealtime - this.d) & Long.MAX_VALUE);
        uVar.b = enumC3602d5;
        uVar.c = this.c;
        uVar.d = Integer.valueOf(i & SubsamplingScaleImageView.TILE_SIZE_AUTO);
        mVar.d = new L5(uVar);
        this.a.a(new com.quizlet.data.repository.widget.b(mVar), EnumC3610e5.ON_DEVICE_DOCUMENT_SCANNER_UI_FINISH);
        this.b.p(this.e, jCurrentTimeMillis, enumC3602d5.a);
    }
}
