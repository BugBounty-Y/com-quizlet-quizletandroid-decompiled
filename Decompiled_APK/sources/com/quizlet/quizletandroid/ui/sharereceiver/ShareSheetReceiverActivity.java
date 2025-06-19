package com.quizlet.quizletandroid.ui.sharereceiver;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.webkit.MimeTypeMap;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.core.app.W;
import androidx.core.content.c;
import androidx.core.content.e;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.quizlet.data.model.m2;
import com.quizlet.data.repository.set.f;
import com.quizlet.quizletandroid.ui.group.i;
import dagger.hilt.internal.b;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

@Metadata
/* loaded from: classes3.dex */
public final class ShareSheetReceiverActivity extends AbstractActivityC0055k implements b, dagger.hilt.android.internal.migration.a {
    public com.quizlet.login.authentication.login.a c;
    public volatile dagger.hilt.android.internal.managers.b d;
    public final Object e = new Object();
    public boolean f = false;
    public f g;

    public ShareSheetReceiverActivity() {
        addOnContextAvailableListener(new i(this, 21));
    }

    public static void C(ShareSheetReceiverActivity shareSheetReceiverActivity, String str, ArrayList arrayList, int i) {
        String str2 = (i & 1) != 0 ? null : str;
        ArrayList arrayList2 = (i & 2) != 0 ? null : arrayList;
        shareSheetReceiverActivity.getClass();
        W w = new W(shareSheetReceiverActivity);
        w.a(u.i(shareSheetReceiverActivity, m2.a, str2, arrayList2, null, 16));
        w.e();
    }

    public final void B(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof b) {
            com.quizlet.login.authentication.login.a aVarB = x().b();
            this.c = aVarB;
            if (aVarB.l()) {
                this.c.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return x().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        B(bundle);
        String action = getIntent().getAction();
        if (action != null) {
            int iHashCode = action.hashCode();
            if (iHashCode == -1173264947) {
                if (action.equals("android.intent.action.SEND")) {
                    z();
                    return;
                }
                return;
            }
            if (iHashCode != -58484670) {
                if (iHashCode == 1703997026 && action.equals("android.intent.action.PROCESS_TEXT")) {
                    z();
                    return;
                }
                return;
            }
            if (action.equals("android.intent.action.SEND_MULTIPLE")) {
                Intent intent = getIntent();
                ArrayList<Uri> arrayListA = Build.VERSION.SDK_INT >= 34 ? e.a(intent, "android.intent.extra.STREAM", Uri.class) : intent.getParcelableArrayListExtra("android.intent.extra.STREAM");
                if (arrayListA != null) {
                    ArrayList arrayList = new ArrayList(C.q(arrayListA, 10));
                    for (Uri uri : arrayListA) {
                        Intrinsics.d(uri);
                        arrayList.add(y(uri));
                    }
                    C(this, null, new ArrayList(arrayList), 1);
                }
            }
        }
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.c;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.f;
    }

    public final dagger.hilt.android.internal.managers.b x() {
        if (this.d == null) {
            synchronized (this.e) {
                try {
                    if (this.d == null) {
                        this.d = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.d;
    }

    public final Uri y(Uri uri) throws IOException {
        f fVar = this.g;
        if (fVar == null) {
            Intrinsics.m("fileHelper");
            throw null;
        }
        String uriString = uri.toString();
        Intrinsics.checkNotNullExpressionValue(uriString, "toString(...)");
        Intrinsics.checkNotNullParameter(uriString, "uriString");
        com.quizlet.quizletandroid.ui.common.images.capture.a aVar = (com.quizlet.quizletandroid.ui.common.images.capture.a) fVar.c;
        Uri uri2 = (Uri) aVar.h(uriString);
        Intrinsics.checkNotNullParameter(uriString, "uriString");
        Uri uri3 = (Uri) aVar.h(uriString);
        Context context = (Context) fVar.b;
        String type = context.getContentResolver().getType(uri3);
        File fileCreateTempFile = File.createTempFile("temp", AbstractC0147y.d(".", type == null ? "png" : MimeTypeMap.getSingleton().getExtensionFromMimeType(type)), context.getCacheDir());
        Intrinsics.checkNotNullExpressionValue(fileCreateTempFile, "createTempFile(...)");
        Uri uriFromFile = Uri.fromFile(fileCreateTempFile);
        InputStream inputStreamOpenInputStream = context.getContentResolver().openInputStream(uri2);
        if (inputStreamOpenInputStream != null) {
            try {
                OutputStream outputStreamOpenOutputStream = context.getContentResolver().openOutputStream(uriFromFile);
                if (outputStreamOpenOutputStream != null) {
                    try {
                        AbstractC3332e.b(inputStreamOpenInputStream, outputStreamOpenOutputStream);
                        outputStreamOpenOutputStream.close();
                    } finally {
                    }
                }
                inputStreamOpenInputStream.close();
            } finally {
            }
        }
        String string = uriFromFile.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        Uri uri4 = Uri.parse(string);
        Intrinsics.checkNotNullExpressionValue(uri4, "parse(...)");
        return uri4;
    }

    public final void z() {
        Uri uri;
        Uri uriY;
        if (!Intrinsics.b(getIntent().getType(), "text/plain")) {
            String type = getIntent().getType();
            if (((type == null || !D.r(type, "image/", false)) && !Intrinsics.b(getIntent().getType(), "application/pdf")) || (uri = (Uri) c.e(getIntent(), "android.intent.extra.STREAM", Uri.class)) == null || (uriY = y(uri)) == null) {
                return;
            }
            C(this, null, B.f(uriY), 1);
            return;
        }
        String stringExtra = getIntent().getStringExtra("android.intent.extra.SUBJECT");
        if (stringExtra == null) {
            stringExtra = "";
        }
        String stringExtra2 = getIntent().getStringExtra("android.intent.extra.TEXT");
        if (stringExtra2 != null) {
            if (stringExtra.length() > 0) {
                stringExtra = ((Object) stringExtra) + "/n";
            }
            stringExtra = ((Object) stringExtra) + stringExtra2;
        }
        String stringExtra3 = getIntent().getStringExtra("android.intent.extra.PROCESS_TEXT");
        if (stringExtra3 != null) {
            if (stringExtra.length() > 0) {
                stringExtra = ((Object) stringExtra) + "/n";
            }
            stringExtra = ((Object) stringExtra) + stringExtra3;
        }
        C(this, stringExtra, null, 2);
    }
}
