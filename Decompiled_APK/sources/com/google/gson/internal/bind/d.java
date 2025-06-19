package com.google.gson.internal.bind;

import com.google.gson.JsonSyntaxException;
import com.google.gson.q;
import java.lang.reflect.Type;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class d extends q {
    public static final a c = new a(1);
    public final /* synthetic */ int a = 0;
    public final Object b;

    public d() {
        ArrayList arrayList = new ArrayList();
        this.b = arrayList;
        Locale locale = Locale.US;
        arrayList.add(DateFormat.getDateTimeInstance(2, 2, locale));
        if (!Locale.getDefault().equals(locale)) {
            arrayList.add(DateFormat.getDateTimeInstance(2, 2));
        }
        if (com.google.gson.internal.g.a >= 9) {
            arrayList.add(new SimpleDateFormat("MMM d, yyyy h:mm:ss a", locale));
        }
    }

    @Override // com.google.gson.q
    public final Object a(com.google.gson.stream.a aVar) {
        switch (this.a) {
            case 0:
                if (aVar.l0() == 9) {
                    aVar.a0();
                    return null;
                }
                String strD0 = aVar.d0();
                synchronized (this) {
                    Iterator it2 = ((ArrayList) this.b).iterator();
                    while (it2.hasNext()) {
                        try {
                            return ((DateFormat) it2.next()).parse(strD0);
                        } catch (ParseException unused) {
                        }
                    }
                    try {
                        return com.google.gson.internal.bind.util.a.b(strD0, new ParsePosition(0));
                    } catch (ParseException e) {
                        throw new JsonSyntaxException(strD0, e);
                    }
                }
            default:
                return ((q) this.b).a(aVar);
        }
    }

    public d(com.google.gson.k kVar, q qVar, Type type) {
        this.b = qVar;
    }
}
