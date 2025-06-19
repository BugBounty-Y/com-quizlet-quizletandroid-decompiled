package com.braze.triggers.events;

import com.braze.models.outgoing.BrazeProperties;

/* loaded from: classes.dex */
public abstract class j extends i implements c {
    public final BrazeProperties e;

    public j(BrazeProperties brazeProperties, com.braze.models.i iVar) {
        this.c = iVar;
        this.e = brazeProperties;
    }
}
