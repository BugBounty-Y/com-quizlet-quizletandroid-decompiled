package com.amazon.device.ads;

/* loaded from: classes.dex */
class StateProperty extends MraidStringProperty {
    MraidStateType stateType;

    public StateProperty(MraidStateType mraidStateType) {
        super("state");
        this.stateType = mraidStateType;
    }

    @Override // com.amazon.device.ads.MraidStringProperty
    public String getValue() {
        return this.stateType.toString();
    }
}
