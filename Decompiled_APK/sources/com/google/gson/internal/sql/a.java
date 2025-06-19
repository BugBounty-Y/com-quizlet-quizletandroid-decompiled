package com.google.gson.internal.sql;

import com.google.gson.JsonSyntaxException;
import com.google.gson.q;
import java.sql.Date;
import java.sql.Time;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;

/* loaded from: classes2.dex */
public final class a extends q {
    public static final com.google.gson.internal.bind.a c = new com.google.gson.internal.bind.a(4);
    public static final com.google.gson.internal.bind.a d = new com.google.gson.internal.bind.a(5);
    public static final com.google.gson.internal.bind.a e = new com.google.gson.internal.bind.a(6);
    public final /* synthetic */ int a;
    public final Object b;

    public a(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new SimpleDateFormat("hh:mm:ss a");
                break;
            default:
                this.b = new SimpleDateFormat("MMM d, yyyy");
                break;
        }
    }

    @Override // com.google.gson.q
    public final Object a(com.google.gson.stream.a aVar) {
        switch (this.a) {
            case 0:
                synchronized (this) {
                    if (aVar.l0() == 9) {
                        aVar.a0();
                        return null;
                    }
                    try {
                        return new Date(((SimpleDateFormat) this.b).parse(aVar.d0()).getTime());
                    } catch (ParseException e2) {
                        throw new JsonSyntaxException(e2);
                    }
                }
            case 1:
                synchronized (this) {
                    if (aVar.l0() == 9) {
                        aVar.a0();
                        return null;
                    }
                    try {
                        return new Time(((SimpleDateFormat) this.b).parse(aVar.d0()).getTime());
                    } catch (ParseException e3) {
                        throw new JsonSyntaxException(e3);
                    }
                }
            default:
                java.util.Date date = (java.util.Date) ((q) this.b).a(aVar);
                if (date != null) {
                    return new Timestamp(date.getTime());
                }
                return null;
        }
    }

    public a(q qVar) {
        this.a = 2;
        this.b = qVar;
    }
}
