package com.fasterxml.uuid;

import com.airbnb.lottie.network.d;
import java.util.Random;

/* loaded from: classes.dex */
public final class c {
    public final d a = new d(22, false);
    public final Random b;
    public int c;
    public long d;
    public long e;
    public int f;

    public c(Random random) {
        this.d = 0L;
        this.e = 0L;
        this.f = 0;
        this.b = random;
        int iNextInt = random.nextInt();
        this.c = iNextInt;
        this.f = (iNextInt >> 16) & 255;
        this.d = 0L;
        this.e = 0L;
    }
}
