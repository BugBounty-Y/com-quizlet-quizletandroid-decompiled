package androidx.core.view.inputmethod;

import android.content.ClipData;
import android.content.ClipDescription;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputConnectionWrapper;
import android.view.inputmethod.InputContentInfo;
import androidx.appcompat.widget.C0116w;
import androidx.camera.camera2.internal.C0132i;
import androidx.compose.ui.text.C0981a;
import androidx.core.view.C1046f;
import androidx.core.view.InterfaceC1044e;
import androidx.core.view.V;
import com.airbnb.lottie.network.d;
import com.google.android.gms.auth.api.signin.internal.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b extends InputConnectionWrapper {
    public final /* synthetic */ int a = 0;
    public final Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(androidx.emoji2.viewsintegration.b inputConnection, C0981a shouldDeleteSurroundingText) {
        super(inputConnection, true);
        Intrinsics.checkNotNullParameter(inputConnection, "inputConnection");
        Intrinsics.checkNotNullParameter(shouldDeleteSurroundingText, "shouldDeleteSurroundingText");
        this.b = shouldDeleteSurroundingText;
    }

    @Override // android.view.inputmethod.InputConnectionWrapper, android.view.inputmethod.InputConnection
    public boolean commitContent(InputContentInfo inputContentInfo, int i, Bundle bundle) {
        Bundle bundle2;
        InterfaceC1044e hVar;
        switch (this.a) {
            case 0:
                h hVar2 = inputContentInfo == null ? null : new h(new d(inputContentInfo, 12), 13);
                C0132i c0132i = (C0132i) this.b;
                if ((i & 1) != 0) {
                    try {
                        ((InputContentInfo) ((d) hVar2.b).b).requestPermission();
                        InputContentInfo inputContentInfo2 = (InputContentInfo) ((d) hVar2.b).b;
                        bundle2 = bundle == null ? new Bundle() : new Bundle(bundle);
                        bundle2.putParcelable("androidx.core.view.extra.INPUT_CONTENT_INFO", inputContentInfo2);
                    } catch (Exception e) {
                        Log.w("InputConnectionCompat", "Can't insert content from IME; requestPermission() failed", e);
                    }
                } else {
                    bundle2 = bundle;
                }
                ClipDescription description = ((InputContentInfo) ((d) hVar2.b).b).getDescription();
                d dVar = (d) hVar2.b;
                ClipData clipData = new ClipData(description, new ClipData.Item(((InputContentInfo) dVar.b).getContentUri()));
                if (Build.VERSION.SDK_INT >= 31) {
                    hVar = new h(clipData, 2);
                } else {
                    C1046f c1046f = new C1046f();
                    c1046f.b = clipData;
                    c1046f.c = 2;
                    hVar = c1046f;
                }
                hVar.n(((InputContentInfo) dVar.b).getLinkUri());
                hVar.j(bundle2);
                if (V.k((C0116w) c0132i.b, hVar.build()) == null) {
                }
                break;
        }
        return super.commitContent(inputContentInfo, i, bundle);
    }

    @Override // android.view.inputmethod.InputConnectionWrapper, android.view.inputmethod.InputConnection
    public boolean deleteSurroundingText(int i, int i2) {
        switch (this.a) {
            case 1:
                ((C0981a) this.b).invoke(Integer.valueOf(i), Integer.valueOf(i2));
                return Boolean.TRUE.booleanValue() && super.deleteSurroundingText(i, i2);
            default:
                return super.deleteSurroundingText(i, i2);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(InputConnection inputConnection, C0132i c0132i) {
        super(inputConnection, false);
        this.b = c0132i;
    }
}
