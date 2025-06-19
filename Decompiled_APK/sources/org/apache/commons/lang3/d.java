package org.apache.commons.lang3;

import java.io.Serializable;

/* loaded from: classes3.dex */
public final class d implements Serializable {
    public final c a = c.a;
    public transient int b;
    public final Integer c;
    public final Integer d;
    public transient String e;

    public d(Integer num, Integer num2) {
        if (num.compareTo(num2) < 1) {
            this.d = num;
            this.c = num2;
        } else {
            this.d = num2;
            this.c = num;
        }
    }

    public final boolean a(Integer num) {
        if (num == null) {
            return false;
        }
        this.a.getClass();
        return num.compareTo(this.d) > -1 && num.compareTo(this.c) < 1;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj == null || obj.getClass() != d.class) {
            return false;
        }
        d dVar = (d) obj;
        return this.d.equals(dVar.d) && this.c.equals(dVar.c);
    }

    public final int hashCode() {
        int i = this.b;
        if (i != 0) {
            return i;
        }
        int iHashCode = this.c.hashCode() + ((this.d.hashCode() + ((d.class.hashCode() + 629) * 37)) * 37);
        this.b = iHashCode;
        return iHashCode;
    }

    public final String toString() {
        if (this.e == null) {
            StringBuilder sb = new StringBuilder("[");
            sb.append(this.d);
            sb.append("..");
            this.e = assistantMode.refactored.a.l(sb, this.c, "]");
        }
        return this.e;
    }
}
