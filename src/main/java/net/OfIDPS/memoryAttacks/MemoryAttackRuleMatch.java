package net.OfIDPS.memoryAttacks;

public class MemoryAttackRuleMatch {
    private int action=Integer.MAX_VALUE;
    public int getAction() {
        return action;
    }
    public void setAction(int action) {
        this.action = action;
    }
    public boolean isMatch() {
        return match;
    }
    public void setMatch(boolean match) {
        this.match = match;
    }
    private boolean match=false;

}
