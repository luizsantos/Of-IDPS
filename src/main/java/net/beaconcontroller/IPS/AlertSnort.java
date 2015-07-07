package net.beaconcontroller.IPS;

public class AlertSnort {
    // Snort alert identification
    int id=-1;
    // Snort alert description
    String description="Not found";
    
    public int getId() {
        return id;
    }
    public void setId(int id) {
        this.id = id;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    
}
