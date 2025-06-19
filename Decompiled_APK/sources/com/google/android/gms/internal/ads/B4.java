package com.google.android.gms.internal.ads;

import android.content.pm.ApkChecksum;
import android.content.pm.PackageManager$OnChecksumsReadyListener;
import androidx.core.view.AbstractC1042d;
import java.util.List;

/* loaded from: classes2.dex */
public final class B4 implements PackageManager$OnChecksumsReadyListener {
    public final /* synthetic */ int a;
    public final C1985dw b;

    public /* synthetic */ B4(C1985dw c1985dw) {
        this.a = 1;
        this.b = c1985dw;
    }

    public final void onChecksumsReady(List list) {
        int i = 0;
        C1985dw c1985dw = this.b;
        switch (this.a) {
            case 0:
                if (list == null) {
                    c1985dw.g("");
                    break;
                } else {
                    try {
                        int size = list.size();
                        while (i < size) {
                            ApkChecksum apkChecksumE = AbstractC1042d.e(list.get(i));
                            if (apkChecksumE.getType() == 8) {
                                Tu tuD = Tu.d.d();
                                byte[] value = apkChecksumE.getValue();
                                c1985dw.g(tuD.g(value.length, value));
                                break;
                            } else {
                                i++;
                            }
                        }
                    } catch (Throwable unused) {
                    }
                    c1985dw.g("");
                    break;
                }
            default:
                if (list == null) {
                    c1985dw.g(null);
                    break;
                } else {
                    try {
                        int size2 = list.size();
                        for (int i2 = 0; i2 < size2; i2++) {
                            ApkChecksum apkChecksumE2 = AbstractC1042d.e(list.get(i2));
                            if (apkChecksumE2.getType() == 8) {
                                byte[] value2 = apkChecksumE2.getValue();
                                char[] cArr = AbstractC1865b5.a;
                                int length = value2.length;
                                char[] cArr2 = new char[length + length];
                                while (i < value2.length) {
                                    byte b = value2[i];
                                    char[] cArr3 = AbstractC1865b5.a;
                                    int i3 = i + i;
                                    cArr2[i3] = cArr3[(b & 255) >>> 4];
                                    cArr2[i3 + 1] = cArr3[b & 15];
                                    i++;
                                }
                                c1985dw.g(new String(cArr2));
                                break;
                            }
                        }
                        c1985dw.g(null);
                        break;
                    } catch (Throwable unused2) {
                        c1985dw.g(null);
                    }
                }
        }
    }

    public B4() {
        this.a = 0;
        this.b = new C1985dw();
    }
}
