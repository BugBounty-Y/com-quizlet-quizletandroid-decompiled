package com.google.gson.internal.bind;

import com.google.gson.q;
import com.google.gson.r;
import com.google.gson.reflect.TypeToken;
import java.util.Calendar;
import java.util.GregorianCalendar;

/* loaded from: classes2.dex */
public final class g implements r {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;

    public /* synthetic */ g(q qVar, int i) {
        this.a = i;
        this.b = qVar;
    }

    @Override // com.google.gson.r
    public final q b(com.google.gson.k kVar, TypeToken typeToken) {
        switch (this.a) {
            case 0:
                if (typeToken.a == Number.class) {
                    break;
                }
                break;
            default:
                Class cls = typeToken.a;
                if (cls == Calendar.class || cls == GregorianCalendar.class) {
                    break;
                }
                break;
        }
        return (h) this.b;
    }

    public String toString() {
        switch (this.a) {
            case 1:
                return "Factory[type=" + Calendar.class.getName() + "+" + GregorianCalendar.class.getName() + ",adapter=" + ((h) this.b) + "]";
            default:
                return super.toString();
        }
    }
}
