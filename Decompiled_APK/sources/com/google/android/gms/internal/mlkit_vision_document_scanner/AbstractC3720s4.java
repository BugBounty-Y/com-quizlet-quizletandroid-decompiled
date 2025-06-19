package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.s4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3720s4 {
    public static final /* synthetic */ int a = 0;

    public static String a(int i) {
        ArrayList arrayList = new ArrayList();
        if (i >= 1) {
            arrayList.add(1);
            int i2 = 2;
            if (i >= 2) {
                arrayList.add(2);
                while (true) {
                    int i3 = i2 - 1;
                    int i4 = i2 - 2;
                    if (i < ((Integer) arrayList.get(i4)).intValue() + ((Integer) arrayList.get(i3)).intValue()) {
                        break;
                    }
                    arrayList.add(Integer.valueOf(((Integer) arrayList.get(i4)).intValue() + ((Integer) arrayList.get(i3)).intValue()));
                    i2++;
                }
            }
        }
        StringBuilder sb = new StringBuilder("1");
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            int iIntValue = ((Integer) arrayList.get(size)).intValue();
            if (i >= iIntValue) {
                sb.insert(0, "1");
                i -= iIntValue;
            } else {
                sb.insert(0, "0");
            }
        }
        return sb.toString();
    }
}
