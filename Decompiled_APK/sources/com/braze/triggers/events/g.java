package com.braze.triggers.events;

/* loaded from: classes.dex */
public final class g extends i {
    public final String e;

    public g(String str, com.braze.models.outgoing.event.push.b bVar) {
        this.c = bVar;
        this.e = i.a(str);
    }

    @Override // com.braze.triggers.events.b
    public final String a() {
        return "push_click";
    }
}
