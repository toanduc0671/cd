# Kubernetes As A Service

## How to work and develop

- Clone this reo to personal PC
- Checkout to extract branch
- Get submodule data: git submodule update --init --recursive
- Modify data
- Push changes to centre git repository

## Install K8S with only monitoring and logging stack

- Copy example inventory to your inventory: `cp -R inventory/example inventory/cluster-1
- Prepare your inventory file in `inventory/cluster-1/inventory.ini`
- Change values of `inventory/cluster-1/kube-prometheus-stack-values` if needed
- For pushing alerts from internal prometheus to external alert managers, make
sure that you declare external alert managers in `group_vars/all/all.yml`as below:
    ```yaml
    alert_managers:
      - 10.240.226.2:9091
      - 10.240.226.3:9091
    ```
- Run `ansible-playbook` command to install K8S with monitoring stack:
    ```shell
    ansible-playbook -f 20 -i inventory/cluster-stagging-2/inventory.ini \
    --user=vt_admin --ask-pass --ask-become-pass \ 
    --become  --become-method=su --become-user=root \
    advanced-cluster-with-monitoring-logging.yml
    ```

    Before run this command, suppose that `ansible`, `ansible-playbook` are installed
    in your ansible controller host.

## Supported  Platform

- OpenStack
