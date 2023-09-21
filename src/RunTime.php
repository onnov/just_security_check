<?php

namespace JustSecurityCheck\Console;

use DateTime;
use Exception;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class RunTime extends Command
{
    private $res = 0;
    protected function configure()
    {
        $this->setName('run:time')
            ->setAliases(['time', 't'])
            ->setDescription('Check for security advisories for the packages in your composer.json')
            ->addOption('dev', 'd', InputOption::VALUE_NONE, 'If require-dev should be checked as well')
            ->addOption('date', 'D', InputOption::VALUE_REQUIRED, 'Max package date.')
            ->addOption(
                'allow',
                ['exclude', 'E', 'e', 'A', 'a'],
                InputOption::VALUE_REQUIRED,
                'Exclude some vulnerabilities,'
            );
    }

    /**
     * @throws Exception
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        if (!$input->getOption('date')) {
            $output->writeln('<fg=red>Set the max package date !</>');

            return 1;
        }
        $maxDate = new DateTime($input->getOption('date'));

        $allow = [];
        if ($input->getOption('allow')) {
            $allow = array_fill_keys(explode(',', $input->getOption('allow')), 1);
        }

        $dir = getcwd() . '/';

        if (!file_exists($dir . 'composer.lock')) {
            $output->writeln('<fg=red>No composer.lock file found !</>');

            return 1;
        }

        $composerLock = file_get_contents($dir . 'composer.lock');

        $json = json_decode($composerLock, true);

        if (!array_key_exists('packages', $json)) {
            $output->writeln('<fg=red>There is no "require" !</>');
            return 1;
        }

        if ($input->getOption('dev')) {
            if (!array_key_exists('packages-dev', $json)) {
                $output->writeln('<fg=red>There is no "require-dev" !</>');
                return 1;
            }
        }

        $this->parsePackages($json['packages'], $maxDate, $allow, $output);

        if ($input->getOption('dev')) {
            $this->parsePackages($json['packages-dev'], $maxDate, $allow, $output);
        }

        return $this->res;
    }

    /**
     * @param array $packages
     * @param DateTime $maxDate
     * @param array $allow
     * @return void
     * @throws Exception
     */
    private function parsePackages($packages, $maxDate, $allow, $output)
    {
        foreach ($packages as $package) {
            $pTime = new DateTime($package['time']);
            if ($pTime > $maxDate) {
                $this->res = 1;
                $output
                    ->writeln(
                        '<fg=green>' . $package['name'] . '</> <fg=red>(' . $package['version'] .
                        ')'.$pTime->format('Y-m-d').'</>'
                    );
            }
        }
    }
}
