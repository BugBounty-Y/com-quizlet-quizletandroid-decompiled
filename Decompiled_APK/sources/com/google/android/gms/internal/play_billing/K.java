package com.google.android.gms.internal.play_billing;

import androidx.appcompat.widget.C0122z;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import java.util.Arrays;

/* loaded from: classes2.dex */
public enum K {
    RESPONSE_CODE_UNSPECIFIED(-999),
    /* JADX INFO: Fake field, exist only in values array */
    SERVICE_TIMEOUT(-3),
    /* JADX INFO: Fake field, exist only in values array */
    FEATURE_NOT_SUPPORTED(-2),
    /* JADX INFO: Fake field, exist only in values array */
    SERVICE_DISCONNECTED(-1),
    /* JADX INFO: Fake field, exist only in values array */
    OK(0),
    /* JADX INFO: Fake field, exist only in values array */
    USER_CANCELED(1),
    /* JADX INFO: Fake field, exist only in values array */
    SERVICE_UNAVAILABLE(2),
    /* JADX INFO: Fake field, exist only in values array */
    BILLING_UNAVAILABLE(3),
    /* JADX INFO: Fake field, exist only in values array */
    ITEM_UNAVAILABLE(4),
    /* JADX INFO: Fake field, exist only in values array */
    DEVELOPER_ERROR(5),
    /* JADX INFO: Fake field, exist only in values array */
    ERROR(6),
    /* JADX INFO: Fake field, exist only in values array */
    ITEM_ALREADY_OWNED(7),
    /* JADX INFO: Fake field, exist only in values array */
    ITEM_NOT_OWNED(8),
    /* JADX INFO: Fake field, exist only in values array */
    EXPIRED_OFFER_TOKEN(11),
    /* JADX INFO: Fake field, exist only in values array */
    NETWORK_ERROR(12);

    public static final W c;
    public final int a;

    static {
        C0122z c0122z = new C0122z(15, (char) 0);
        c0122z.c = new Object[8];
        c0122z.b = 0;
        for (K k : values()) {
            Integer numValueOf = Integer.valueOf(k.a);
            int i = c0122z.b + 1;
            Object[] objArr = (Object[]) c0122z.c;
            int length = objArr.length;
            int i2 = i + i;
            if (i2 > length) {
                c0122z.c = Arrays.copyOf(objArr, AbstractC2027eu.e(length, i2));
            }
            Object[] objArr2 = (Object[]) c0122z.c;
            int i3 = c0122z.b;
            int i4 = i3 + i3;
            objArr2[i4] = numValueOf;
            objArr2[i4 + 1] = k;
            c0122z.b = i3 + 1;
        }
        C c2 = (C) c0122z.d;
        if (c2 != null) {
            throw c2.a();
        }
        W wA = W.a(c0122z.b, (Object[]) c0122z.c, c0122z);
        C c3 = (C) c0122z.d;
        if (c3 != null) {
            throw c3.a();
        }
        c = wA;
    }

    K(int i) {
        this.a = i;
    }
}
