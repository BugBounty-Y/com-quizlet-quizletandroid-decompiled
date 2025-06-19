package androidx.emoji2.text;

import android.content.pm.PackageManager;
import android.content.pm.Signature;

/* loaded from: classes.dex */
public final class c extends com.quizlet.shared.usecase.folderstudymaterials.c {
    @Override // com.quizlet.shared.usecase.folderstudymaterials.c
    public final Signature[] p(PackageManager packageManager, String str) {
        return packageManager.getPackageInfo(str, 64).signatures;
    }
}
