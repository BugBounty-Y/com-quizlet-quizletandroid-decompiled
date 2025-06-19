package com.iabtcf.decoder;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.iabtcf.exceptions.UnsupportedVersionException;
import com.iabtcf.utils.l;
import com.iabtcf.utils.n;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;

/* loaded from: classes2.dex */
public interface b {
    static b d(String str, a... aVarArr) {
        e eVar;
        EnumSet enumSetNoneOf = EnumSet.noneOf(a.class);
        for (a aVar : aVarArr) {
            enumSetNoneOf.add(aVar);
        }
        String[] strArrSplit = str.split("\\.");
        com.iabtcf.utils.a aVar2 = new com.iabtcf.utils.a(Base64.getUrlDecoder().decode(strArrSplit[0]));
        byte bI = aVar2.i(l.e);
        if (bI == 1) {
            return new c(aVar2);
        }
        if (bI != 2) {
            throw new UnsupportedVersionException(AbstractC0147y.c(bI, "Version ", "is unsupported yet"));
        }
        if (strArrSplit.length > 1) {
            com.iabtcf.utils.a[] aVarArr2 = new com.iabtcf.utils.a[strArrSplit.length - 1];
            for (int i = 1; i < strArrSplit.length; i++) {
                aVarArr2[i - 1] = new com.iabtcf.utils.a(Base64.getUrlDecoder().decode(strArrSplit[i]));
            }
            eVar = new e(aVar2, aVarArr2);
        } else {
            eVar = new e(aVar2, new com.iabtcf.utils.a[0]);
        }
        if (!enumSetNoneOf.contains(a.a)) {
            eVar.hashCode();
        }
        return eVar;
    }

    List a();

    n b();

    n c();

    int e();

    int f();
}
