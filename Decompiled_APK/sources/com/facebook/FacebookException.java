package com.facebook;

import com.braze.L;
import com.facebook.internal.C1563s;
import com.facebook.internal.EnumC1562q;
import java.util.Random;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public class FacebookException extends RuntimeException {
    public static final /* synthetic */ int a = 0;

    public FacebookException() {
    }

    @Override // java.lang.Throwable
    public String toString() {
        String message = getMessage();
        return message == null ? "" : message;
    }

    public FacebookException(String str) {
        super(str);
        Random random = new Random();
        if (str == null || !o.o.get() || random.nextInt(100) <= 50) {
            return;
        }
        C1563s.a(new L(str, 1), EnumC1562q.ErrorReport);
    }
}
